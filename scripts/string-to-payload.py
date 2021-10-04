INPUT_STRING = "%3Cscript%3E"

characters = []
for i in range(len(INPUT_STRING)):
    characters.append(f"'{INPUT_STRING[i]}'")
output = "{" + ", ".join(characters) + "}"

print(output)
