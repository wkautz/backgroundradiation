

d = dict()
srcIPCount = dict()
dstIPCount = dict()

def extractData(line):
    global d, srcIPCount
    arr = line.split(";")
    arr[2] = arr[2][:-1]
    arr = map(int, arr)

    srcIP = arr[0]
    dstIP = arr[1]
    port = arr[2]

    if (srcIPCount.get(srcIP) == None):
        srcIPCount[srcIP] = 1
    else:
        srcIPCount[srcIP] += 1

    if (dstIPCount.get(dstIP) == None):
        dstIPCount[dstIP] = 1
    else:
        dstIPCount[dstIP] += 1

    for key in srcIPCount.keys():
        if (srcIPCount[key] > 1):
            print(str(key) + ";" + str(srcIPCount[key]) + "\n")


    #d[arr[0]] = arr[1:]

def main():
    global d
    raw_file = open('otherPacks.txt', 'r')

    for line in raw_file:
        extractData(line)


main()