#!/usr/bin/python

class Employer:
    empcount=0

    def __init__(self,name,salary):
        self.name = name
        self.salary = salary
        Employer.empcount += 1

    def displaycount(self):
        print  "toatal employer count:%d" % Employer.empcount

    def displayemployee(self):
        print "name:",self.name,",salary:",self.salary


emp1 = Employer("Zara",2000)
emp2 = Employer("Zalar",3000)

emp1.displaycount()
emp1.displayemployee()
emp2.displaycount()
emp2.displayemployee()