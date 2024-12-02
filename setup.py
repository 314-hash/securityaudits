from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="blockchain-security-audit-toolkit",
    version="0.1.0",
    author="314-hash",
    author_email="",
    description="A comprehensive Python-based toolkit for blockchain and DeFi smart contract security audits",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/314-hash/securityaudits.github.io",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.13",
    install_requires=requirements,
)
