# volshell script (-w --script ... --script-only): prints RSVOLJSON{...} with the kernel DTB, PsLoadedModuleList,
# PsActiveProcessHead, MmPfnDatabase value, KdDebuggerDataBlock and MmPhysicalMemoryBlock runs of a Windows
# image - the header values mk_crashdump_from_raw.py needs.
import json
k = self.config['kernel']
kernel = self.context.modules[k]
layer = self.context.layers[kernel.layer_name]
sym = kernel.symbol_table_name
out = {}
for name in ['MmPhysicalMemoryBlock', 'PsLoadedModuleList', 'PsActiveProcessHead', 'MmPfnDatabase', 'KdDebuggerDataBlock']:
    try:
        out[name] = kernel.get_symbol(name).address + kernel.offset
    except Exception as e:
        out[name] = None
ptr = kernel.object(object_type='pointer', offset=out['MmPhysicalMemoryBlock'] - kernel.offset)
desc = kernel.object(object_type='_PHYSICAL_MEMORY_DESCRIPTOR', offset=int(ptr), absolute=True)
runs = []
desc.Run.count = desc.NumberOfRuns
for r in desc.Run:
    runs.append((int(r.BasePage), int(r.PageCount)))
out['runs'] = runs
out['NumberOfPages'] = int(desc.NumberOfPages)
if out['MmPfnDatabase']:
    out['PfnDataBase'] = int(kernel.object(object_type='pointer', offset=out['MmPfnDatabase'] - kernel.offset))
out['dtb'] = layer.config['page_map_offset']
print('RSVOLJSON' + json.dumps(out))
