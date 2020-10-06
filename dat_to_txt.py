old_file = open("./public_suffix_list.dat.txt", encoding="utf-8")
file_txt = old_file.read()
new_file = open("tld_list.txt", "w", encoding="utf-8")
file_txt_arr = file_txt.splitlines()
for line in file_txt_arr:
    if line[:2] != "//" and line[:2] != "":
        new_file.write(line)
        new_file.write("\n")
