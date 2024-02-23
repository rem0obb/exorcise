# Exorcise: Malware Analysis Engine : Documentation


# Contents

* [Run Engine](#runengine)
* [Drivers](#drivers)


## Run Engine


Our engine utilizes the YARA library to perform comprehensive scans based on our [YARA-Mindshield-Analysis](rules/YARA-Mindshield-Analysis) database. To execute a scan using YARA rules, follow the instructions below:

```bash
exorcise -r /YARA-Mindshield-Analysis -p /home -f
```

Ensure that the appropriate YARA rules are present in the `/YARA-Mindshield-Analysis` directory before running the command. This command will analyze the `/home` directory for matches with the YARA rules in the database.

Parameters:
- `-r` - YARA rules, any file with a `.yar` extension is considered a YARA rule.
- `-p` - The path to the file or directory.
- `-f` - Informs the engine whether the provided path is a file or directory.

If you want more details about the analysis, you can use the `--verbose` command.


## Drivers

Currently the engine uses a driver called pyscho, which resides in the [drivers](/drivers/pyscho/) folder.

To check if the driver is installed on your machine, you can execute the following command:

```bash
exorcise --ispyscho
```

This command will inform you whether the driver is installed on your machine or not.

---

To connect with the driver, simply execute the following command:

```bash
exorcise --connect-pyscho
```

