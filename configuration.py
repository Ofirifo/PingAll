#input_json_file = r"D:/Desktop/input_ex.json"
log_file = r"D:/Desktop/example.txt"
output_json_file = r"D:/Desktop/sample.json"
directory_input_json_file = r"D:/Desktop/input_ex/"


#Example of input
json_input_format = {
    "segment": [
        {
            "target": "222.104.100.0/24",
            "packets": 4,
            "exclude": [
                "222.104.100.1-13",
				"222.104.100.15-18",
                "222.104.100.200-212"
            ]
        },
		{
            "target": "222.104.102.0/24",
            "packets": 4,
            "exclude": [
                "222.104.102.1",
                "222.104.102.3"
            ]
        }
    ],
    "manual": [
        {
            "target": "222.104.102.0/24",
            "is_ping": True,
            "packets": 4,
            "port": None
        },
        {
            "target": "222.104.102.0/24",
            "is_ping": False,
            "packets": None,
            "port": 32
        }
    ]

}

#Example of output
json_output_format = [
             {
                "ip": "current_ip",
                "ping": "true",
                "port": "null",
                "status": "true"
             },
             {
                "ip": "current_ip",
                "ping": "false",
                "port": 21,
                "status": "true"
             }
     ]

