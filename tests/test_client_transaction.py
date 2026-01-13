from twitter_generator import ClientTransactionGenerator

if __name__ == "__main__":
    generator = ClientTransactionGenerator(
        open("./fixtures/ondemand.js", "r").read(),
        open("./fixtures/home.html", "r").read(),
    )
    print(generator.generate("GET", "/api/1.1/statuses/user_timeline.json"))


    print(generator.generate("POST", "/api/1.1/statuses/user_timeline.json"))