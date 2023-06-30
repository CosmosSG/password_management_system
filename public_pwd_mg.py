from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from enum import Enum
import pandas as pd
import  getpass, os, time, subprocess, time, wcwidth

user_key = b'user_key'
user_iv = b'user_iv'
password_key = b'password_key'
password_iv = b'password_iv'
user_delimiter = b'user_delimiter'
user_end = b'user_end'
password_delimiter = b'password_delimiter'
password_end = b'password_end'

def generate_key_iv(key_length=32, iv_length=16):
    key = get_random_bytes(key_length)
    iv = get_random_bytes(iv_length)
    return key, iv

class ChoWork(Enum):
    USER = 1
    PWD = 2
    OTHER = 3

class CryptoSystem():
    def __init__(self, cho):
        self.cho = cho
        if(self.cho == ChoWork.USER):
            self.key = user_key
            self.iv =  user_iv
        elif(self.cho == ChoWork.PWD):
            self.key = password_key
            self.iv = password_iv
        else:
            self.key = None
            self.iv = None

    def set_key(self, key, iv):
        self.key = key
        self.iv = iv

    def encryption(self, text):
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        text = pad(text.encode('utf-8'), AES.block_size)
        cipher_text = self.cipher.encrypt(text)
        return cipher_text

    def decryption(self, text):
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decryption_text = self.cipher.decrypt(text)
        decryption_text = decryption_text[:-decryption_text[-1]]
        return decryption_text.decode('utf-8')

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


class Setup():
    def __init__(self):
        self.delimiter = user_delimiter
        self.end = user_end
        clear()
        print("Please register as a user because we could not find your login information.")
        self.username = str(input("Enter username: "))
        while self.username == "":
            clear()
            print("Please include your name.")
            self.username = str(input("Enter username: "))
        self.password = str(getpass.getpass("Enter password: "))
        re_password = str(getpass.getpass("Retype password: "))
        while self.password != re_password or len(self.password) < 5:
            clear()
            if(self.password != re_password):
                print("Passwords do not match. Please try again.")
            elif(len(self.password) < 5):
                print("Please set at least 5 characters.")
            print("Username:", self.username)
            self.password = str(getpass.getpass("Enter password: "))
            re_password = str(getpass.getpass("Retype password: "))
        self.save_setup()

    def save_setup(self):
        crypto = CryptoSystem(ChoWork.USER)
        with open("pwd_mg_data/setting.data", "wb") as f:
            f.write(crypto.encryption(self.username))
            f.write(self.delimiter)
            f.write(crypto.encryption(self.password))
            f.write(self.end)

def file_checker(filename):
    try:
        f = open(f'pwd_mg_data/{filename}')
        return True
    except FileNotFoundError:
        create_directory()
        return False
    
def create_directory():
    directory = "pwd_mg_data"
    if not os.path.exists(directory):
        os.mkdir(directory)
        subprocess.check_call(["attrib", "+H", directory])

def userpassword_read():
    delimiter = user_delimiter
    end = user_end
    if not file_checker("setting.data"):
        return False
    else:
        crypto = CryptoSystem(ChoWork.USER)
        with open("pwd_mg_data/setting.data", "rb") as f:
            tmp1 = f.read().split(end)
            filedata = []
            for i in range(len(tmp1)):
                filedata.append(tmp1[i].split(delimiter))
    username = crypto.decryption(filedata[0][0])
    password = crypto.decryption(filedata[0][1])
    return username, password, filedata

def userpassword_checker():
    username, password, f = userpassword_read()
    clear()
    print("Enter username and password to log in")
    inp_username = str(input("Enter username: "))
    inp_password = str(getpass.getpass("Enter password: "))
    count = 0
    while inp_username != username or inp_password != password:
        clear()
        print(f"Username and password do not match. ({3-count} times remaining)")
        inp_username = str(input("Enter username: "))
        inp_password = str(getpass.getpass("Enter password: "))
        if (count >= 2):
            print("Username and password do not match.")
            exit(1)
        count += 1
    print("Successful login.")
    time.sleep(2)

def operation_selection():
    select_message = """======================================    
1: Registration
2: Search
3: Change of registration information
--------------------------------------
exit: Exit System
setting: Change Login Information
======================================"""
    while True:
        clear()
        print(select_message)
        select_inp = str(input("> "))
        while select_inp not in {"1", "2", "3", "exit", "setting"}:
            clear()
            print(select_message)
            print("ERROR: Input value is incorrect.")
            select_inp = str(input("> "))
        if select_inp == "1":
            registration()
        elif select_inp == "2":
            search()
        elif select_inp == "3":
            edit_registration_info()
        elif select_inp == "exit":
            print("Password manager data saved.")
            time.sleep(2)
            exit(1)
        elif select_inp == "setting":
            edit_login_info()

def registration():
    delimiter = password_delimiter
    end = password_end
    clear()
    print("<< Registration >>\nIf you want to leave it blank, enter 'none'.")
    registered_name = str(input("Registered name: "))
    while registered_name == "":
        clear()
        print("<< Registration >>\nIf you want to leave it blank, enter 'none'.\nERROR: Check the input values\n")
        registered_name = str(input("Registered name: "))
    site_url = str(input("Site URL: "))
    while site_url == "":
        clear()
        print("<< Registration >>\nIf you want to leave it blank, enter 'none'.\nERROR: Check the input values\n")
        print("Registered Name:", registered_name)
        site_url = str(input("Site URL: "))
    account_name = str(input("Account Name: "))
    while account_name == "":
        clear()
        print("<< Registration >>\nIf you want to leave it blank, enter 'none'.\nERROR: Check the input values\n")
        print("Registered Name:", registered_name)
        print("Site URL:", site_url)
        account_name = str(input("Account Name: "))
    password = str(getpass.getpass("Password: "))
    re_password = str(getpass.getpass("Retype password: "))
    while password != re_password:
        clear()
        print("<< Registration >>\nIf you want to leave it blank, enter 'none'.\nERROR: Passwords do not match. Please try again.\n")
        print("Registered Name:", registered_name)
        print("Site URL:", site_url)
        print("Account Name:", account_name)
        password = str(getpass.getpass("Enter password: "))
        re_password = str(getpass.getpass("Retype password: "))
    crypto = CryptoSystem(ChoWork.PWD)
    with open("pwd_mg_data/setting.data", "ab") as f:
        f.write(crypto.encryption(registered_name))
        f.write(delimiter)
        f.write(crypto.encryption(site_url))
        f.write(delimiter)
        f.write(crypto.encryption(account_name))
        f.write(delimiter)
        f.write(crypto.encryption(password))
        f.write(end)
    print("Successful registration.")
    time.sleep(2)


def read_password_file():
    try:
        delimiter = password_delimiter
        end = password_end
        p_end = user_end
        with open("pwd_mg_data/setting.data", "rb") as f:
            tmp = f.read().split(p_end)
            tmp1 = tmp[1].split(end)
            tmp2 = []
            for i in range(len(tmp1)):
                tmp2.append(tmp1[i].split(delimiter))
            tmp2 = tmp2[:-1]
            tmp3 = []
            crypto = CryptoSystem(ChoWork.PWD)
            for i in range(len(tmp2)):
                inner_list = []
                for j in range(len(tmp2[i])):
                    inner_list.append(crypto.decryption(tmp2[i][j]))
                tmp3.append(inner_list)
        df_pwd = pd.DataFrame(tmp3, columns=["Registered Name", "Site URL", "Account Name", "Password"])
        if df_pwd.empty:
            return None
        else:
            return df_pwd
    
    except FileNotFoundError:
        return None
    
def write_password_file(df_pwd):
    delimiter = password_delimiter
    end = password_end
    p_end = user_end
    crypto = CryptoSystem(ChoWork.PWD)
    with open("pwd_mg_data/setting.data", "rb") as f:
        tmp = f.read().split(p_end)
        tmp1 = tmp[0] + p_end

        tmp2 = df_pwd.values.tolist()

        tmp3 = b''
        for i in range(len(tmp2)):
            for j in range(len(tmp2[i])):
                if (j != 0):
                    if j == len(tmp2[i]) - 1:
                        tmp3 += crypto.encryption(tmp2[i][j])
                    else:
                        tmp3 += crypto.encryption(tmp2[i][j]) + delimiter
            tmp3 += end
        tmp4 = tmp1 + tmp3
    with open("pwd_mg_data/setting.data", "wb") as f:
        f.write(tmp4)
def search():
    df_pwd = read_password_file()
    if df_pwd is None:
        clear()
        message = """+============================+
| ERROR: Not yet registered. |
+============================+      
"""
        print(message)
        time.sleep(2)
        return 0
    clear()
    df_pwd.insert(0, "PW_Id", [str(i) for i in range(len(df_pwd))])
    while True:
        keyword = str(input("<< Search >>\nSearch keyword (or type 'end' to exit): "))
        clear()
        if keyword in {"end", "exit"}:
            break

        # 部分一致検索
        filtered_df = df_pwd[
            (df_pwd['Registered Name'].str.contains(keyword, case=False)) |
            (df_pwd['Site URL'].str.contains(keyword, case=False)) |
            (df_pwd['Account Name'].str.contains(keyword, case=False))
        ]
        if filtered_df.empty:
            message = f"""+============================+
 No results found for keyword:
 > {keyword}
+============================+
"""
            clear()
            print(message)
        else:
            new_df = pd.DataFrame(filtered_df, columns=["PW_Id", "Registered Name", "Site URL", "Account Name", "Password"])


            max_lengths = [max(len(str(column)), new_df[column].astype(str).map(lambda x: wcwidth.wcswidth(str(x)) if x is not None else 0).max()) for column in new_df.columns]
            table = '<< Search Result >>\n'
            table += '+' + '+'.join(['-' * (length + 2) for length in max_lengths]) + '+\n'
            for column, length in zip(new_df.columns, max_lengths):
                table += f'| {column:<{length}} '
            table += '|\n'
            table += '+' + '+'.join(['-' * (length + 2) for length in max_lengths]) + '+\n'
            for _, row in new_df.iterrows():
                for column, length in zip(new_df.columns, max_lengths):
                    cell = str(row[column])
                    count = 0
                    for c in cell:
                        width = wcwidth.wcwidth(c)
                        if width == 2:
                            count += 1
                    if count == 0:
                        table += f'| {str(row[column]):<{length}} '
                    else:
                        table += f'| {cell:<{length - (count-1)}}'
                        
                table += '|\n+' + '+'.join(['-' * (length + 2) for length in max_lengths]) + '+\n'
            # table += '+' + '+'.join(['-' * (length + 2) for length in max_lengths]) + '+\n'

            print("\n" + table)

def edit_registration_info():
    df_pwd = read_password_file()
    if df_pwd is None:
        clear()
        message = """+============================+
| ERROR: Not yet registered. |
+============================+      
"""
        print(message)
        time.sleep(2)
        return 0
    df_pwd.insert(0, "PW_Id", [str(i) for i in range(len(df_pwd))])
    while True:
        clear()
        keyword = str(input("<< Searching for data to edit >>\nSearch keyword (or type 'end' to exit): "))
        if keyword in {"end", "exit"}:
            break

        filtered_df = df_pwd[
            (df_pwd['Registered Name'].str.contains(keyword, case=False)) |
            (df_pwd['Site URL'].str.contains(keyword, case=False)) |
            (df_pwd['Account Name'].str.contains(keyword, case=False))
        ]
        if filtered_df.empty:
            message = f"""+============================+
 No results found for keyword:
 > {keyword}
+============================+
"""
            clear()
            print(message)
        else:
            new_df = pd.DataFrame(filtered_df, columns=["PW_Id", "Registered Name", "Site URL", "Account Name", "Password"])

            max_lengths = [max(len(str(column)), new_df[column].astype(str).map(lambda x: wcwidth.wcswidth(str(x)) if x is not None else 0).max()) for column in new_df.columns]
            table = '<< Search Result >>\n'
            table += '+' + '+'.join(['=' * (length + 2) for length in max_lengths]) + '+\n'
            for column, length in zip(new_df.columns, max_lengths):
                table += f'| {column:<{length}} '
            table += '|\n'
            table += '+' + '+'.join(['=' * (length + 2) for length in max_lengths]) + '+\n'
            for _, row in new_df.iterrows():
                for column, length in zip(new_df.columns, max_lengths):
                    cell = str(row[column])
                    count = 0
                    for c in cell:
                        width = wcwidth.wcwidth(c)
                        if width == 2:
                            count += 1
                    if count == 0:
                        table += f'| {str(row[column]):<{length}} '
                    else:
                        table += f'| {cell:<{length - (count-1)}}'
                        
                table += '|\n+' + '+'.join(['-' * (length + 2) for length in max_lengths]) + '+\n'

            print("\n" + table)


            pw_id = str(input("Enter the PW_Id of the record you want to edit: "))
            if pw_id not in new_df['PW_Id'].values:
                print("Invalid PW_Id. Please try again.")
                time.sleep(2)
                continue

            record = new_df.loc[new_df['PW_Id'] == pw_id]
            clear()
            print("Record to be edited:")
            max_lengths = [max(len(str(column)), record[column].astype(str).map(lambda x: wcwidth.wcswidth(str(x)) if x is not None else 0).max()) for column in record.columns]
            table = '<< Search Result >>\n'
            table += '+' + '+'.join(['=' * (length + 2) for length in max_lengths]) + '+\n'
            for column, length in zip(record.columns, max_lengths):
                table += f'| {column:<{length}} '
            table += '|\n'
            table += '+' + '+'.join(['=' * (length + 2) for length in max_lengths]) + '+\n'
            for _, row in record.iterrows():
                for column, length in zip(record.columns, max_lengths):
                    cell = str(row[column])
                    count = 0
                    for c in cell:
                        width = wcwidth.wcwidth(c)
                        if width == 2:
                            count += 1
                    if count == 0:
                        table += f'| {str(row[column]):<{length}} '
                    else:
                        table += f'| {cell:<{length - (count-1)}}'
                        
                table += '|\n+' + '+'.join(['-' * (length + 2) for length in max_lengths]) + '+\n'

            print("\n" + table)
            confirm = str(input("Is this the record you want to edit? [Y/n]: "))
            if confirm.lower() == "no":
                continue

            action = str(input("What action would you like to take? (edit/delete): "))
            if action.lower() == "delete":
                df_pwd = df_pwd[df_pwd['PW_Id'] != pw_id]
                write_password_file(df_pwd)
                print("Record deleted successfully.")
                time.sleep(2)
            elif action.lower() == "edit":
                clear()
                print("<< Edit Registration Information >>")
                print("Leave a field blank to keep the current value.")

                new_registered_name = str(input(f"Registered Name (original data=[{record['Registered Name'].values[0]}]): "))
                new_site_url = str(input(f"Site URL (original data=[{record['Site URL'].values[0]}]): "))
                new_account_name = str(input(f"Account Name (original data=[{record['Account Name'].values[0]}]): "))
                new_password = str(input(f"Password (original data=[{record['Password'].values[0]}]): "))


                df_pwd.loc[df_pwd['PW_Id'] == pw_id, 'Registered Name'] = new_registered_name if new_registered_name != "" else record['Registered Name'].values[0]
                df_pwd.loc[df_pwd['PW_Id'] == pw_id, 'Site URL'] = new_site_url if new_site_url != "" else record['Site URL'].values[0]
                df_pwd.loc[df_pwd['PW_Id'] == pw_id, 'Account Name'] = new_account_name if new_account_name != "" else record['Account Name'].values[0]
                df_pwd.loc[df_pwd['PW_Id'] == pw_id, 'Password'] = new_password if new_password != "" else record['Password'].values[0]


                write_password_file(df_pwd)

                print("Record edited successfully.")
                time.sleep(2)
            else:
                print("Invalid action. Please try again.")
                time.sleep(2)




def edit_login_info():
    delimiter = user_delimiter
    end = user_end
    username, password, filedata = userpassword_read()
    clear()
    message = """<< Edit Login Info >>
Edit login password or username?    
1. username
2. password"""
    print(message)
    select_inp = str(input("> "))
    while select_inp not in ["1", "2"]:
        clear()
        print(message)
        print("ERROR: Check input values.")
        select_inp = str(input("> "))
    if select_inp == "1":
        clear()
        print("+=============================+\n| Enter your changed username |\n+=============================+")
        inp_username = str(input(f"Enter username (original value={username}): "))
        while inp_username == "":
            clear()
            print("+=============================+\n| Enter your changed username |\n+=============================+")
            print("ERROR: Check input values.")
            inp_username = str(input(f"Enter username (original value={username}): "))
        inp_password = password
    elif select_inp == "2":
        inp_password = str(getpass.getpass(f"Enter password (original value={password}): "))
        re_inp_password = str(getpass.getpass("Retype password: "))
        while inp_password != re_inp_password or len(inp_password) < 5:
            clear()
            if(inp_password != re_inp_password):
                print("Passwords do not match. Please try again.")
            elif(len(inp_password) < 5):
                print("Please set at least 5 characters.")
            inp_password = str(getpass.getpass(f"Enter password: "))
            re_inp_password = str(getpass.getpass("Retype password: "))
        inp_username = username
    crypto = CryptoSystem(ChoWork.USER)
    filedata[0][0] = crypto.encryption(inp_username)
    filedata[0][1] = crypto.encryption(inp_password)
    with open("pwd_mg_data/setting.data", "wb") as f:
        f.write(end.join([delimiter.join(item) for item in filedata]))
    message = """+======================+  
| Successfully changed |
+======================+    
"""
    time.sleep(2)



def main():
    try:
        if(file_checker("setting.data") == False):
            setup = Setup()
        userpassword_checker()
        operation_selection()
    except KeyboardInterrupt:
        exit(1)
        
if __name__ == "__main__":
    main()
