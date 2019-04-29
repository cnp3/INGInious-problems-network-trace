from setuptools import setup, find_packages

setup(
    name="inginious-problems-network-trace",
    version="0.2.dev0",
    description="TODO",
    packages=find_packages(),
    install_requires=["inginious", "PyYAML"],
    tests_require=[],
    extras_require={},
    scripts=[],
    author="Maxime Piraux",
    author_email="inginious@info.ucl.ac.be",
    license="GNU AGPL 3",
    url="https://github.com/CNP3/INGInious-problems-network-trace",
    include_package_data=True
)
