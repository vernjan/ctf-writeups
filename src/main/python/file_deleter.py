import csv
import os

file_duplicates = r"C:\Users\vernj\Downloads\DPFResultsDate_638361101749568852.csv"

with open(file_duplicates) as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count == 0:
            print(f'Column names are {", ".join(row)}')
            line_count += 1
        else:
            marked = row[1]
            if marked == "1":
                path = row[4]
                print(f"Deleting {path} with mark: {marked}")
                os.remove(path)
            line_count += 1

    print(f'Processed {line_count} lines.')
