import os
import pandas as pd

# Function to classify the protocol based on the file name

from src.pyflowmeter.sniffer import create_sniffer

def convert2csv(name,output):
    sniffer = create_sniffer(

                input_file=name,
                to_csv=True,
                output_file=output,
                verbose=True,
                sending_interval=5
            )

    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        print('Stopping the sniffer')
        sniffer.stop()

def classify_protocol(file_name):
    # Classify the protocol based on the file name
    if "zeronet" in file_name.lower():
        label = "Zeronet"
    elif "i2p" in file_name.lower():
        label = "I2P"
    elif "freenet" in file_name.lower():
        label = "Freenet"
    elif "tor" in file_name.lower():
        label = "Tor"
    elif "vpn" in file_name.lower():
        label = "VPN"
    else:
        label = "Normal"
    
    return label

# Function to classify the behavior based on the file name
def classify_behavior(file_name):
    # Classify the behavior based on the file name
    if "browsing" in file_name.lower():
        label_2 = "Browsing"
    elif "audio" in file_name.lower():
        label_2 = "Audio"
    elif "video" in file_name.lower():
        label_2 = "Video"
    elif "chat" in file_name.lower():
        label_2 = "Chat"
    elif "ftp" in file_name.lower() or "file" in file_name.lower():
        label_2 = "FTP"
    elif "voip" in file_name.lower():
        label_2 = "VOIP"
    elif "email" in file_name.lower()  or "mail" in file_name.lower():
        label_2 = "Email"
    elif "p2p" in file_name.lower():
        label_2 = "P2P"
    else:
        label_2 = "Browsing"
    
    return label_2

# Specify the folder containing the CSV files
Folders = [
    ('Freenet', 'Freenet_CSV'), 
    ('I2P', 'I2P_CSV'), 
    ('Zeronet', 'Zeronet_CSV'), 
    ('VPN', 'VPN_CSV'), 
    ('Tor', 'Tor_CSV'), 
    ('Normal', 'Normal_CSV')
]

folder_path = r"/home/safesurf/Desktop/Intrusion Prevention System code/Pcaps/"


# Read all CSV files in the folder
# for folder,csv in Folders:
#     for file_name in os.listdir(folder_path+folder):
#         if file_name.endswith(".pcap"):
#             convert2csv(folder_path+folder+f'/{file_name}',folder_path+folder+f'/CSV_{file_name}.csv')
#             print(f" {folder_path+folder}+f'/{file_name} converted and seved on {folder_path+folder}/CSV_{file_name}.csv")


for folder,csv in Folders:
    for file_name in os.listdir(folder_path+folder):
        if file_name.endswith(".csv"):
            # Read the CSV file
            file_path = os.path.join(folder_path+folder, file_name)
            df = pd.read_csv(file_path)

            # Add Label and Label_2 based on the file name
            label = classify_protocol(file_name)
            label_2 = classify_behavior(file_name)
            
            # Add the Label and Label_2 columns to every row
            df["Label"] = label
            df["Label_2"] = label_2

            # Save the updated file with new labels
            new_file_path = os.path.join(folder_path+csv, f"csv_{file_name}")
            df.to_csv(new_file_path, index=False)

            print(f"Added Label and Label_2 to all rows in file {file_name} and saved as {new_file_path}")
