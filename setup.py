from setuptools import setup, find_packages

setup(
    name="inginious-problems-network-trace",
    version="0.1.dev0",
    description="TODO",
    packages=find_packages(),
    install_requires=["inginious", "quic-tracker-dissector", "dpkt", "PyYAML"],
    tests_require=[],
    extras_require={},
    scripts=[],
    author="Maxime Piraux",
    author_email="inginious@info.ucl.ac.be",
    license="GNU AGPL 3",
    url="https://github.com/UCL-INGI/INGInious-problems-network-trace",
    include_package_data=True
)
