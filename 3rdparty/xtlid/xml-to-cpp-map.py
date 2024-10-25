import xml.etree.ElementTree as ET
from typing import Dict
import sys

def parse_xml_file_to_cpp_map(filename: str) -> Dict[str, Dict[str, str]]:
    """
    Parse XML file and return a dictionary of library names and their function mappings
    """
    try:
        # Parse the XML file
        tree = ET.parse(filename)
        root = tree.getroot()
        
        # Dictionary to store results for each library
        results = {}
        
        # Process each library
        for lib in root.findall('lib'):
            lib_name = lib.get('name')
            functions = {}
            
            # Process each function in the library
            for func in lib.findall('func'):
                # Convert the hex string to int and back to hex for consistent formatting
                func_id = int(func.get('id'), 16)
                func_name = func.get('name')
                functions[func_id] = func_name
                
            results[lib_name] = functions
            
        return results
    except FileNotFoundError:
        print(f"Error: Could not find file '{filename}'")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Error: Invalid XML in file '{filename}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        sys.exit(1)

def generate_cpp_maps(mappings: Dict[str, Dict[str, str]]) -> str:
    """
    Generate C++ unordered_map declarations from the parsed data
    """
    cpp_output = []
    
    for lib_name, functions in mappings.items():
        # Create map declaration
        cpp_output.append(f"// Function mappings for {lib_name}")
        cpp_output.append(f"std::unordered_map<uint32_t, std::string> functions_{lib_name} = {{")
        
        # Add each function mapping
        entries = []
        for func_id, func_name in sorted(functions.items()):
            entries.append(f"  {{ 0x{func_id:x}, \"{func_name}\" }}")
            
        # Join entries with commas
        cpp_output.append(",\n".join(entries))
        
        # Close the map declaration
        cpp_output.append("};")
        cpp_output.append("")  # Empty line between libraries
        
    return "\n".join(cpp_output)

def main():
    # Use xtlid.xml as the input file
    filename = "xtlid.xml"
    
    try:
        # Parse XML file and generate output
        mappings = parse_xml_file_to_cpp_map(filename)
        cpp_output = generate_cpp_maps(mappings)
        print(cpp_output)
        
    except Exception as e:
        print(f"Error: Failed to process XML file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
