class Person:
    total_people = 0  # Class variable to keep track of the total number of people

    def __init__(self, name):
        self.name = name
        Person.total_people += 1  # Increment the total number of people when a new Person instance is created

    @classmethod
    def display_total_people(cls):
        print("Total number of people:", cls.total_people)

Person
Person.display_total_people()