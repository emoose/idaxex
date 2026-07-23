import json

import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_idaapi
import ida_loader
import ida_name
import ida_nalt
import ida_pro
import ida_segment


def segment_for_ea(ea):
    return ida_segment.get_segment_ea(ea) != ida_idaapi.BADADDR


input_path = ida_nalt.get_input_file_path()
file_type = ida_loader.get_file_type_name()
processor = ida_ida.inf_get_procname()
start_ea = ida_ida.inf_get_start_ea()
errors = []
warnings = []
segments = []
loaded_segments = 0

for index in range(ida_segment.get_segm_qty()):
    segment = ida_segment.segment_info_t()
    if not ida_segment.get_segment_info_by_num(
        segment, index, ida_segment.GSI_NAME
    ):
        errors.append("segment %d is unavailable" % index)
        continue

    start = int(segment.start_ea)
    end = int(segment.end_ea)
    if start >= end:
        errors.append("segment %d has an invalid range" % index)

    if segments and start < segments[-1]["end_ea"]:
        errors.append("segment %d overlaps the preceding segment" % index)

    loaded = ida_bytes.is_loaded(start)
    if loaded:
        loaded_segments += 1

    segments.append(
        {
            "index": index,
            "name": segment.get_name(),
            "start_ea": start,
            "end_ea": end,
            "size": end - start,
            "permissions": int(segment.get_perm()),
            "start_loaded": bool(loaded),
        }
    )

function_count = ida_funcs.get_func_qty()
orphan_functions = 0
for index in range(function_count):
    function_ea = ida_funcs.get_func_ea_by_num(index)
    if function_ea == ida_idaapi.BADADDR or not segment_for_ea(function_ea):
        orphan_functions += 1

entry_count = ida_entry.get_entry_qty()
orphan_entries = 0
for index in range(entry_count):
    ordinal = ida_entry.get_entry_ordinal(index)
    ea = ida_entry.get_entry(ordinal)
    if ea != ida_idaapi.BADADDR and not segment_for_ea(ea):
        orphan_entries += 1

if not file_type.startswith("Xbox"):
    errors.append("unexpected file type: %s" % file_type)
if processor.upper() != "PPC":
    errors.append("unexpected processor: %s" % processor)
if not segments:
    errors.append("loader created no segments")
if segments and not loaded_segments:
    errors.append("no segment begins with loaded data")
if start_ea != ida_idaapi.BADADDR and not segment_for_ea(start_ea):
    errors.append("start address is outside all segments")
if orphan_functions:
    errors.append("%d functions begin outside all segments" % orphan_functions)
if orphan_entries:
    errors.append("%d entry points are outside all segments" % orphan_entries)
if function_count == 0:
    warnings.append("database contains no functions")
if entry_count == 0:
    warnings.append("database contains no entry points")

result = {
    "schema": 1,
    "input": input_path,
    "file_type": file_type,
    "processor": processor,
    "start_ea": int(start_ea),
    "segment_count": len(segments),
    "loaded_segment_count": loaded_segments,
    "function_count": function_count,
    "entry_count": entry_count,
    "name_count": ida_name.get_nlist_size(),
    "import_module_count": int(ida_nalt.get_import_module_qty()),
    "segments": segments,
    "warnings": warnings,
    "errors": errors,
    "passed": not errors,
}

print("[idaxex-verify] %s" % json.dumps(result, sort_keys=True))
ida_pro.qexit(0 if result["passed"] else 1)
