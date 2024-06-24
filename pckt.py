import csv
import random

def random_packet_size():
  """Generates a random packet size between 64 and 1500 bytes."""
  return random.randint(64, 1500)

def read_and_append_csv(input_file, output_file):
  """Reads a CSV file, fills in random packet sizes, and appends a new column to the output file."""
  with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
    reader = csv.reader(infile)
    writer = csv.writer(outfile)
    # Read header row and add "pkt_size" column
    header = next(reader)
    header.append("pkt_size")
    writer.writerow(header)
    # Read data rows, generate random packet size, and write with new column
    for row in reader:
      packet_size = random_packet_size()
      row.append(packet_size)
      writer.writerow(row)

# Replace with your input and output file paths
input_file = "SDN-ARP-dataset.csv"
output_file = "SDN-dataset.csv"
read_and_append_csv(input_file, output_file)
print("CSV processed and written to", output_file)
