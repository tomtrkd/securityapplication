import csv
import pickle

with open('top-1m.csv') as f:
    reader = csv.reader(f)
    data = list(reader)

top1m= set()
for line in data:
    top1m.add(line[1])

print(top1m)
file_out = open("top1m.pickle","wb")
pickle.dump(top1m, file_out)
file_out.close()