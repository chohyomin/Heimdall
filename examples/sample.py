import os
import subprocess
import pickle


def run(user_cmd: str):
    # user_cmd is user-controlled
    os.system("echo safe")  # constant command (should be lower severity)
    os.system(user_cmd)  # cmd injection sink
    subprocess.run(user_cmd, shell=True)  # high severity


def load_blob(blob: bytes):
    return pickle.loads(blob)  # unsafe deserialization


def demo():
    cmd = input("cmd> ")
    run(cmd)

