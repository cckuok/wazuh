# DBSync Testing Tool
## Index
1. [Purpose](#purpose)
2. [Compile Wazuh](#compile-wazuh)
3. [How to use the tool](#how-to-suse-the-tool)

## Purpose
The DBSync Testing Tool was created to test and validate the correct 

## Compile Wazuh
In order to run unit tests on a specific wazuh target, the project needs to be built with the `DEBUG` and `TEST` options as shown below:
```
make deps RESOURCES_URL=file:///path/to/deps/
make TARGET=server|agent DEBUG=1 TEST=1
```

## How to use the tool
In order to run the `dbsync_test_tool` utility the following steps need to be accomplished:
1) Create a config json file with the following structure:
```
{
    "db_name": "db_name",
    "db_type": "1",
    "host_type": "<0|1>",
    "persistance": "",
    "sql_statement":"sql"
}
```
Where:
  - db_name: Database name to be used.
  - db_type: Database type to be used. Right now it is being used SQLITE3.
  - host_type: Agent or Manager.
  - persistance: Database type of persistance being used. Not implemented yet.
  - sql_statement: Database sql structure to be created. This structure will be associated the other files needed to used the tool.

2) Create the needed amount of json files representing the different snapshots information. These ones need to follow the sql_statement structure created in the below step.
3) Define an output folder where all resulting data will be located.
4) Once all the below steps are accomplished the tool will be used like this:
```
./dbsync_test_tool -c config.json -s input1.json,input2.json,input3.json -o ./output
```
5) Considering the example below all diff snapshots will be located in ./output folder in the following format: snapshop_1.json, snapshot_2.json ... snapshot_n.json where 'n' will be the number of json files passed as part of the argument "-s".
