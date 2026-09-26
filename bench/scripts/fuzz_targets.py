#!/usr/bin/env python3
"""ISF reading + structure-offset discovery for the rsvol robustness fuzzer.

Reads a volatility3 ISF (JSON, possibly xz) to learn struct sizes, the byte offsets of the
linked-list members inside kernel objects (so a mutant can build a cyclic list), and kernel
symbol addresses. Used by fuzz_images.py. Standard library only.
"""

import json
import lzma


def load_isf(path):
    if path.startswith('file://'):
        path = path[7:]
    op = lzma.open if path.endswith('.xz') else open
    with op(path, 'rb') as f:
        return json.load(f)


def struct_of(isf, name):
    t = isf.get('user_types', {}).get(name)
    if not t:
        return None
    fields = {k: (v.get('offset', 0), v.get('type', {})) for k, v in t.get('fields', {}).items()}
    return {'size': t.get('size', 0), 'fields': fields}


def member_offset(isf, sname, dotted):
    """Byte offset of a dotted member path inside struct sname (descending embedded structs)."""
    off, cur = 0, sname
    for part in dotted.split('.'):
        s = struct_of(isf, cur)
        if not s or part not in s['fields']:
            return None
        o, t = s['fields'][part]
        off += o
        cur = t.get('name') if t.get('kind') in ('struct', 'union') else None
    return off


def symbol_addr(isf, name):
    return isf.get('symbols', {}).get(name, {}).get('address')


# Objects to harvest from clean plugin output: (plugin, offset column, ISF struct, kind label)
OBJ_SOURCES = {
    'windows': [
        ('windows.pslist.PsList', 'Offset(V)', '_EPROCESS', 'proc'),
        ('windows.modules.Modules', 'Offset', '_KLDR_DATA_TABLE_ENTRY', 'module'),
        ('windows.registry.hivelist.HiveList', 'Offset', '_CMHIVE', 'hive'),
        ('windows.threads.Threads', 'Offset', '_ETHREAD', 'thread'),
        ('windows.filescan.FileScan', 'Offset', '_FILE_OBJECT', 'file'),
        ('windows.driverscan.DriverScan', 'Offset', '_DRIVER_OBJECT', 'driver'),
        ('windows.mutantscan.MutantScan', 'Offset', '_KMUTANT', 'mutant'),
        ('windows.vadinfo.VadInfo', 'Offset', '_MMVAD', 'vad'),
    ],
    'linux': [
        ('linux.pslist.PsList', 'OFFSET (V)', 'task_struct', 'task'),
        ('linux.lsmod.Lsmod', 'Offset', 'module', 'module'),
        ('linux.sockstat.Sockstat', 'Sock Offset', 'sock', 'sock'),
        ('linux.pagecache.Files', 'InodeAddr', 'inode', 'inode'),
        ('linux.pagecache.Files', 'SuperblockAddr', 'super_block', 'sb'),
    ],
    'mac': [
        ('mac.pslist.PsList', 'OFFSET', 'proc', 'proc'),
        ('mac.lsmod.Lsmod', 'Offset', 'kmod_info', 'kmod'),
    ],
}

# Linked-list members whose pointers, made to point back at their own node, produce a cyclic list.
LIST_FIELDS = {
    '_EPROCESS': ['ActiveProcessLinks', 'ThreadListHead', 'Pcb.ThreadListHead'],
    '_KLDR_DATA_TABLE_ENTRY': ['InLoadOrderLinks'],
    '_CMHIVE': ['HiveList'],
    '_ETHREAD': ['ThreadListEntry', 'Tcb.ThreadListEntry'],
    'task_struct': ['tasks', 'children', 'sibling', 'thread_group', 'thread_node'],
    'module': ['list'],
    'proc': ['p_list', 'p_children', 'p_sibling'],
}

# Kernel symbols worth clobbering (list heads, syscall tables, callback arrays, kallsyms metadata).
SYMBOLS = {
    'windows': ['PsActiveProcessHead', 'PsLoadedModuleList', 'KiServiceTable', 'KeServiceDescriptorTable',
                'KeServiceDescriptorTableShadow', 'CmpHiveListHead', 'ObpRootDirectoryObject', 'ObTypeIndexTable',
                'PspCreateProcessNotifyRoutine', 'PspLoadImageNotifyRoutine', 'PspCreateThreadNotifyRoutine',
                'KeBugCheckCallbackListHead', 'KeBugCheckReasonCallbackListHead', 'PoolBigPageTable',
                'PoolBigPageTableSize', 'KdDebuggerDataBlock', 'MmPfnDatabase', 'ObHeaderCookie',
                'PsInitialSystemProcess', 'MmUnloadedDrivers', 'MmLastUnloadedDriver', 'KiInitialPCR',
                'IopRootDeviceNode', 'PnpDeviceActionQueue', 'SepRmGlobalSaclHeader', 'ExpTimerDpcRoutine',
                'KiWaitNever', 'KiWaitAlways', 'ObpInfoMaskToOffset', 'EtwpDebuggerData', 'IoDriverObjectType'],
    'linux': ['init_task', 'modules', 'super_blocks', 'net_namespace_list', 'idt_table', 'sys_call_table',
              'keyboard_notifier_list', 'prog_idr', 'tty_drivers', 'init_nsproxy', 'init_pid_ns',
              'prb', 'printk_rb_static', 'kallsyms_names', 'kallsyms_offsets', 'kallsyms_num_syms',
              'kallsyms_token_table', 'kallsyms_token_index', 'kallsyms_markers', 'kallsyms_relative_base',
              'vmcoreinfo_data', 'iomem_resource', 'registered_fb', 'num_registered_fb', 'tcp_hashinfo',
              'mount_hashtable', 'init_mm', 'nf_hooks_needed', 'init_net', 'pid_hash', 'init_files',
              'log_buf', 'log_buf_len', '__per_cpu_offset', 'init_cred', 'linux_banner', 'saved_command_line',
              'mod_tree', 'bpf_prog_types', 'ftrace_ops_list'],
    'mac': ['allproc', 'kmod', 'nsysent', 'sysent', 'sysctl__children', 'mountlist', 'ifnet_head',
            'kauth_scopes', 'mac_policy_list', 'tcbinfo', 'udbinfo', 'real_ncpus', 'version', 'msgbufp',
            'IdlePML4', 'kernel_pmap', 'kernel_map', 'rootvnode', 'nprocs', 'socket_filters',
            'timer_call_queue', 'dlil_ifnet_head', 'master_processor', 'processor_list'],
}
