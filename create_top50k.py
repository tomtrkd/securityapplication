import csv
import pickle

with open('top-1m.csv') as f:
    reader = csv.reader(f)
    data = list(reader)

top50k= set()
for line in data[0:50000]:
    top50k.add(line[1])

print(top50k)
file_out = open("top50k.pickle","wb")
pickle.dump(top50k, file_out)
file_out.close()