import os

def execute_command(user_input):
    os.system("echo " + user_input)

if __name__ == "__main__":
    user_input = input("Enter your input: ")
    execute_command(user_input)