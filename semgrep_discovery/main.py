import argparse

def main():
    parser = argparse.ArgumentParser(description='Semgrep discovery cli')
    parser.add_argument('--wd', type=str, help='Project work directory to scan', required=True)
    parser.add_argument('--langs', type=str, help='Languages to scan', required=True)
    parser.add_argument('--objects', type=str, help='Objects to search', required=True)
    parser.add_argument('--keywords', type=str, help='Sencitive keywords in objects', required=True)

    args = parser.parse_args()
    print(f"Work dir: {args.wd}")
    print(f"Langs: {args.langs}")
    print(f"Objects: {args.objects}")
    print(f"Keywords: {args.keywords}")

if __name__ == "__main__":
    main()