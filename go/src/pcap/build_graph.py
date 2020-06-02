import matplotlib.pyplot as plt

def build_arrays():
    num_ports = []
    frequencies = []
    with open('portscancounts1.txt', 'r') as f:
        for line in f:
            arr = line.strip().split(",")
            num_ports.append(int(arr[0]))
            frequencies.append(int(arr[1]))
    return num_ports, frequencies

def main():
    num_ports, frequencies = build_arrays()

    plt.plot(num_ports, frequencies, 'g-')
    plt.xlabel('Number of Ports Scanned')
    plt.ylabel('Frequency of Port Scan Size')

    plt.grid()
    
    plt.xscale("log")
    plt.savefig('portscancounts.png')
    plt.show()

if __name__ == '__main__':
    main()