import csv

flagmap = dict()

def extractData(row):
    global flagmap

    arr = [12]

    length = len(row)
    for i in range(1, length):
        arr.append(row[i])

    flagmap[row[0]] = arr

    

def main():
    global flagmap
    reader = csv.reader(open('flagMap.csv', 'r'))

    for row in reader:
        if (row[0] == 'IPSrc'): continue
        extractData(row)

    print(flagmap)


main()