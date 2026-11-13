"""Give harvested per-user components stable GUIDs and HKCU key paths."""
import sys
import uuid
import xml.etree.ElementTree as ET

NS = "http://schemas.microsoft.com/wix/2006/wi"
ET.register_namespace("", NS)
path = sys.argv[1]
tree = ET.parse(path)
namespace = uuid.UUID("74a21e70-3a53-4a80-9510-4685e836b7b6")
components = tree.findall(f".//{{{NS}}}Component")
for component in components:
    component_id = component.attrib["Id"]
    component.set("Guid", str(uuid.uuid5(namespace, component_id)).upper())
    component.set("Win64", "yes")
    for file in component.findall(f"{{{NS}}}File"):
        file.attrib.pop("KeyPath", None)
    ET.SubElement(component, f"{{{NS}}}RegistryValue", {
        "Root": "HKCU", "Key": r"Software\NetFlow\Components", "Name": component_id,
        "Type": "integer", "Value": "1", "KeyPath": "yes",
    })
directories = [directory.attrib["Id"] for directory in tree.findall(f".//{{{NS}}}Directory")]
for directory_id in list(reversed(directories)) + ["INSTALLFOLDER", "ProgramsFolder"]:
    ET.SubElement(components[0], f"{{{NS}}}RemoveFolder", {
        "Id": "remove_" + directory_id, "Directory": directory_id, "On": "uninstall",
    })
tree.write(path, encoding="utf-8", xml_declaration=True)
