from setuptools import setup
setup(
    name="pytokenator",
    package_dir={"":"py"},
    py_modules=["gcpblob", "gcpsecrets", "josekeys"],
    entry_points=dict(
        console_scripts=["josekeys=josekeys:run"]
    )
)