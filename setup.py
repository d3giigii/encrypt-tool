from setuptools import setup, find_packages

setup(
    name="encrypt-tool",
    version="1.0.0",
    author="Logan Hammond",
    description="A simple AES encryption/decryption CLI tool",
    packages=find_packages(),
    # Read from requirements.txt
    install_requires=[
        line.strip() for line in open("requirements.txt") if line.strip()
    ],
    entry_points={
        "console_scripts": [
            "encrypt-tool=encrypt_tool.main:cli"
        ]
    },
    python_requires=">3.7"
)