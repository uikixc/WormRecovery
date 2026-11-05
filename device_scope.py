"""Read-only physical-device discovery and partition-aware scan selection."""
import hashlib
import json
import os
from pathlib import Path
from windows_storage import mounted_volumes

INVENTORY_SCRIPT=r"""
$ProgressPreference='SilentlyContinue';$out=@();$issues=@();
$legacy=@(Get-CimInstance Win32_DiskDrive -ErrorAction Stop);
$disks=@(Get-Disk -ErrorAction Stop);
# Enumerate once. A disk without partitions is a valid empty device, not a
# failing filtered query that must abort discovery of every other disk.
$partitions=@(Get-Partition -ErrorAction Stop);
foreach($d in $disks){
 $old=$legacy|Where-Object {$_.Index -eq $d.Number}|Select-Object -First 1;
 $parts=@();foreach($p in @($partitions|Where-Object {$_.DiskNumber -eq $d.Number})){
  $vol=$null;
  try {$vol=$p|Get-Volume -ErrorAction Stop} catch {
   $issues+=@{category='volume_query_failed';disk=[int]$d.Number;partition=[int]$p.PartitionNumber;message=[string]$_.Exception.Message}
  };
  $parts+=@{partition=[int]$p.PartitionNumber;letter=[string]$p.DriveLetter;access=@($p.AccessPaths);volume=[string]$vol.UniqueId;label=[string]$vol.FileSystemLabel;filesystem=[string]$vol.FileSystem;size=[double]$p.Size}
 };
 $out+=@{number=[int]$d.Number;model=[string]$d.FriendlyName;serial=([string]$d.SerialNumber).Trim();unique=[string]$d.UniqueId;pnp=[string]$old.PNPDeviceID;bus=[string]$d.BusType;readonly=[bool]$d.IsReadOnly;offline=[bool]$d.IsOffline;size=[double]$d.Size;partitions=@($parts);partition_status=$(if($parts.Count){'enumerated'}else{'no_partitions'})}
};
$mapped=@($out|ForEach-Object {$_.partitions}|ForEach-Object {[string]$_.letter});
$unmapped=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2 OR DriveType=3' -ErrorAction Stop|Where-Object {$_.DeviceID.Substring(0,1) -notin $mapped}|ForEach-Object {[string]$_.DeviceID});
ConvertTo-Json -InputObject @{schema=1;devices=@($out);issues=@($issues);unmapped_roots=@($unmapped)} -Depth 8 -Compress
"""

LEGACY_INVENTORY_SCRIPT=r"""
$ProgressPreference='SilentlyContinue';$out=@();$issues=@();
foreach($d in @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop)){
 $parts=@();
 try {
  foreach($p in @(Get-CimAssociatedInstance -InputObject $d -Association Win32_DiskDriveToDiskPartition -ErrorAction Stop)){
   foreach($v in @(Get-CimAssociatedInstance -InputObject $p -Association Win32_LogicalDiskToPartition -ErrorAction Stop)){
    $parts+=@{letter=([string]$v.DeviceID).Substring(0,1);partition=[int]$p.Index;volume='';filesystem=[string]$v.FileSystem;size=[double]$v.Size}
   }
  }
 } catch {$issues+=@{category='legacy_association_failed';disk=[int]$d.Index;message=[string]$_.Exception.Message}};
 $bus=[string]$d.InterfaceType;if(([string]$d.PNPDeviceID) -like 'USB*'){$bus='USB'};
 $out+=@{number=[int]$d.Index;model=[string]$d.Model;serial=([string]$d.SerialNumber).Trim();pnp=[string]$d.PNPDeviceID;bus=$bus;offline=$false;size=[double]$d.Size;partitions=@($parts)}
};
ConvertTo-Json -InputObject @{devices=@($out);issues=@($issues)} -Depth 8 -Compress
"""


class DiscoveryError(ValueError):
    def __init__(self,message,details):
        super().__init__(message)
        self.details=details


def compatible_inventory(powershell,primary,initial_issues,volumes=None):
    """Map actual mounted volumes even when the MSFT storage provider disagrees."""
    issues=list(initial_issues);legacy={'devices':[]}
    try:legacy=powershell(LEGACY_INVENTORY_SCRIPT) or legacy
    except Exception as ex:issues.append({'category':'legacy_inventory_failed','message':str(ex)[:1500]})
    issues.extend(legacy.get('issues') or [])
    try:volumes=mounted_volumes() if volumes is None else volumes
    except Exception as ex:
        raise DiscoveryError('无法读取本地卷信息，请查看诊断报告。',{'issues':issues,'native_error':str(ex)[:1500]}) from ex
    old_rows=legacy.get('devices') or []
    if isinstance(old_rows,dict):old_rows=[old_rows]
    # Native disk extents bind Win32_DiskDrive.Index to the mounted volume.
    # No assumption is made that an IDV provider's Get-Disk number is the same.
    devices={};unmapped=[]
    for volume in volumes:
        letter=volume['letter'];numbers=volume.get('disks') or []
        owners=[d for d in old_rows if any(str(p.get('letter','')).casefold()==letter.casefold() for p in d.get('partitions') or [])]
        owner=None;source=None
        if len(numbers)==1:
            owner=next((d for d in old_rows if d['number']==numbers[0]),None)
            if owner is None:owner={'number':numbers[0],'model':'本地存储设备','partitions':[]}
            source='native_volume_extents'
        elif not numbers and len(owners)==1:
            owner=owners[0];source='win32_association'
        elif volume.get('drive_type')==3 and volume.get('bus') in ('Virtual','File Backed Virtual','Storage Spaces'):
            owner={'number':'virtual-volume-'+letter,'model':'虚拟存储卷','partitions':[]};source='native_virtual_volume'
        if owner is None:
            unmapped.append(letter+':');issues.append({'category':'volume_mapping_unresolved','root':letter+':','native':volume})
            continue
        key=str(owner['number'])
        if key not in devices:
            devices[key]={**owner,'partitions':[],'partition_status':'compatibility','discovery_source':source}
            # Preserve modern identifiers only for a matching, nonempty PNP ID.
            for modern in primary.get('devices') or []:
                if owner.get('pnp') and str(modern.get('pnp','')).casefold()==str(owner['pnp']).casefold():
                    devices[key]['unique']=modern.get('unique','')
                    break
        device=devices[key]
        bus=volume.get('bus')
        if bus in ('USB','SD','MMC','1394') or volume.get('drive_type')==2 or volume.get('removable') is True:
            device['bus']=bus if bus in ('USB','SD','MMC','1394') else 'USB'
        elif bus and str(device.get('bus','')).casefold() not in ('usb','sd','mmc','1394'):device['bus']=bus
        if not device.get('bus'):
            unmapped.append(letter+':');issues.append({'category':'volume_bus_unresolved','root':letter+':'})
            continue
        original=next((p for p in owner.get('partitions') or [] if str(p.get('letter','')).casefold()==letter.casefold()),{})
        device['partitions'].append({**original,'letter':letter,'volume':volume.get('volume',''),'mapping_source':source})
        for issue in volume.get('issues') or []:issues.append({**issue,'root':letter+':'})
    return {'schema':1,'devices':list(devices.values()),'issues':issues,'unmapped_roots':unmapped,'discovery_source':'win32_compatibility'}

def root_key(path):
    return os.path.normcase(os.path.abspath(path)).rstrip('\\/')+os.sep

def identifiers(device):
    values=[]
    for field in ('unique','pnp'):
        value=str(device.get(field,'')).strip().casefold()
        if value:values.append(field+':'+hashlib.sha256(value.encode()).hexdigest())
    serial=str(device.get('serial','')).strip().casefold()
    if serial:values.append('serial:'+hashlib.sha256((str(device.get('model','')).casefold()+'|'+serial).encode()).hexdigest())
    return values

def protection_path():
    return Path(os.environ.get('PROGRAMDATA','C:/ProgramData'))/'WormRecovery/device-protection.json'

class DeviceCatalog:
    def __init__(self,rows,protection=None):
        self.discovery_issues=[];self.unmapped_roots=[]
        if isinstance(rows,dict) and 'devices' in rows:
            self.discovery_issues=rows.get('issues') or []
            self.unmapped_roots=rows.get('unmapped_roots') or []
            rows=rows['devices']
        if isinstance(rows,dict):rows=[rows]
        self.devices=[]
        protected_ids=set((protection or {}).get('identifiers',[]))
        protected_volumes={str(x).casefold() for x in (protection or {}).get('volumes',[])}
        for row in rows or []:
            d=dict(row)
            d['identifiers']=identifiers(d)
            d['key']=d['identifiers'][0] if d['identifiers'] else 'unidentified:'+str(d['number'])
            d['external']=str(d.get('bus','')).casefold() in ('usb','sd','mmc','1394')
            parts=d.get('partitions') or []
            if isinstance(parts,dict):parts=[parts]
            for p in parts:
                if not str(p.get('letter','')).isalpha():p['letter']=''
            d['partitions']=parts
            d['roots']=sorted({str(p['letter']).upper()+':'+os.sep for p in parts if len(str(p.get('letter','')))==1 and str(p['letter']).isalpha()})
            d['protected']=bool(protected_ids.intersection(d['identifiers']) or protected_volumes.intersection(str(p.get('volume','')).casefold() for p in parts))
            self.devices.append(d)
    @classmethod
    def discover(cls,powershell):
        path=protection_path()
        protection=json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
        primary={'devices':[]};issues=[];volumes=None
        try:
            primary=powershell(INVENTORY_SCRIPT)
            if not isinstance(primary,dict) or 'devices' not in primary:
                raise ValueError('磁盘接口返回的数据格式无效。')
            # Verify against mounted Win32 volumes, independently of both CIM
            # providers. An empty CIM result must never mean a successful scan.
            volumes=mounted_volumes()
            mapped={str(p.get('letter','')).upper():(d,p) for d in primary.get('devices') or [] for p in d.get('partitions') or [] if p.get('letter')}
            mismatches=[]
            for v in volumes:
                match=mapped.get(v['letter'])
                if match is None or len(v.get('disks') or [])==1 and match[0]['number']!=v['disks'][0]:
                    mismatches.append(v['letter']+':');continue
                if v.get('volume'):match[1]['volume']=v['volume']
                if v.get('bus') in ('USB','SD','MMC','1394') or v.get('drive_type')==2 or v.get('removable') is True:
                    match[0]['bus']=v.get('bus') if v.get('bus') in ('USB','SD','MMC','1394') else 'USB'
            primary['unmapped_roots']=sorted(set(primary.get('unmapped_roots') or [])|set(mismatches))
            if not primary['unmapped_roots']:return cls(primary,protection)
            issues.extend(primary.get('issues') or [])
            issues.append({'category':'primary_mapping_incomplete','roots':primary['unmapped_roots']})
        except Exception as ex:
            issues.append({'category':'primary_inventory_failed','error_type':type(ex).__name__,'message':str(ex)[:1500]})
            if not isinstance(primary,dict):primary={'devices':[]}
        return cls(compatible_inventory(powershell,primary,issues,volumes),protection)
    def device_for_root(self,root):
        key=root_key(root)
        return next((d for d in self.devices if any(root_key(r)==key for r in d['roots'])),None)
    def select(self,mode='internal',manual=None,device_key=None):
        if self.unmapped_roots:
            raise DiscoveryError('磁盘识别未完成：无法确认以下本地卷所属设备：'+'、'.join(self.unmapped_roots)+'。本次未开始扫描，请查看诊断报告。',{'issues':self.discovery_issues,'unmapped_roots':self.unmapped_roots})
        selected=[];skipped=[]
        if manual:
            for path in manual:
                absolute=os.path.abspath(path)
                drive=os.path.splitdrive(absolute)[0]+os.sep
                d=self.device_for_root(drive)
                if d and d['protected']:raise PermissionError('所选设备已在本机排除列表中。')
                if d and d['external']:selected.extend(d['roots'])
                else:selected.append(absolute)
        else:
            for d in self.devices:
                if device_key and d['key']!=device_key:continue
                if mode=='internal' and d['external'] or mode=='removable' and not d['external']:continue
                if d['protected'] or d.get('offline'):skipped.append(d['key']);continue
                selected.extend(d['roots'])
        roots=[]
        for path in selected:
            if not any(root_key(path)==root_key(p) or root_key(path).startswith(root_key(p)) for p in roots):roots.append(path)
        external={}
        for r in roots:
            d=self.device_for_root(os.path.splitdrive(r)[0]+os.sep)
            if d and d['external']:
                part=next(p for p in d['partitions'] if str(p.get('letter','')).casefold()==r[:1].casefold())
                external[r]=part.get('volume','')
        return {'roots':roots,'external_volumes':external,'skipped':skipped,'discovery_issues':self.discovery_issues,
                'excluded_roots':[r for d in self.devices if d['protected'] for r in d['roots']],
                'devices':[{'key':d['key'],'model':d.get('model'),'roots':d['roots'],'protected':d['protected'],'external':d['external'],'discovery_source':d.get('discovery_source','msft_storage'),'partition_status':d.get('partition_status','enumerated' if d['partitions'] else 'no_partitions'),'partitions_without_letters':sum(not p.get('letter') for p in d['partitions'])} for d in self.devices]}

def resolve_scope(powershell,mode='internal',manual=None,device_key=None):
    result=DeviceCatalog.discover(powershell).select(mode,manual,device_key)
    if not result['roots']:raise ValueError('当前扫描范围内没有可用卷。请连接设备或调整扫描范围。')
    if any(not guid for guid in result['external_volumes'].values()):raise ValueError('无法确认设备卷标识，未开始扫描。')
    return result
