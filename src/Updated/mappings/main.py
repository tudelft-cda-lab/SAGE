from src.Updated.mappings import load_IANA_mapping


def main():
    m = load_IANA_mapping()
    print(m)


if __name__ == '__main__':
    main()
