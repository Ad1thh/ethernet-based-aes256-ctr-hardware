# 2026-06-23T22:16:43.915735400
import vitis

client = vitis.create_client()
client.set_workspace(path="AES256")

platform = client.get_component(name="platform")
status = platform.build()

comp = client.get_component(name="app_component")
comp.build()

status = platform.build()

comp.build()

