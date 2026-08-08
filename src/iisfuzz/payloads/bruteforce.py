"""Word-splitting mutation: insert a pattern inside individual path segments."""


def generate_word_mutations(word: str, patterns: list[str]) -> set[str]:
    mutations: set[str] = set()
    for i in range(1, len(word)):
        part1, part2 = word[:i], word[i:]
        for pattern in patterns:
            mutations.add(f"{part1}/{pattern}{part2}")
            mutations.add(f"{part1}{pattern}/{part2}")
    return mutations
