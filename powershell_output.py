"""Decode PowerShell errors without displaying progress CLIXML as an error."""
import re
import xml.etree.ElementTree as ET


def error_text(data):
    if isinstance(data,bytes):
        data=data.decode('utf-16' if data.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig','replace')
    text=str(data).strip()
    if text.startswith('#< CLIXML'):text=text.partition('\n')[2].strip()
    if text.startswith('<Objs'):
        try:
            root=ET.fromstring(text)
            errors=[node.text or '' for node in root.iter() if node.tag.rsplit('}',1)[-1]=='S' and node.get('S')=='Error']
            text=''.join(errors).strip() or 'PowerShell 未返回有效错误说明。'
        except ET.ParseError:text='PowerShell 返回了无法解码的错误记录。'
    return re.sub(r'_x([0-9a-fA-F]{4})_',lambda m:chr(int(m[1],16)),text)
