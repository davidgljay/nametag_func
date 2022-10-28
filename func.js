

# Read and parse from STDIN
body = JSON.parse(STDIN)

# Do something
return_struct = doSomething(body)

# Respond if sync:
STDOUT.write(JSON.generate(return_struct))
