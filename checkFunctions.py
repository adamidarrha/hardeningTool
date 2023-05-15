import cis_audit
import Benchmarks

def compare_functions(data):
    # Get the functions from the other file
    functions = [name for name in dir(cis_audit.LinuxIndependentAudit) if callable(getattr(cis_audit.LinuxIndependentAudit, name)) and not name.startswith("__")]
    for item in data:
        function_name = item.get('function')
        function_name = str(function_name)
        # Check if the function exists in the other file
        if function_name not in functions:
            print(f"Function '{function_name}' does not exist in the other file.")

# Example data
data = Benchmarks.benchmarks["linuxIndependent"]["2.0.0"]

# Call the function with the data
compare_functions(data)
