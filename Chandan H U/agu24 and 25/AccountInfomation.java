import java.util.Date;

public class AccountInfomation {
    private int id;
    private double balance, annualInterestRate;
    private Date dateCreated = new Date();

    AccountInfomation() {
        id = -1;
        balance = 0;
    }

    public void setBalance(double amount) {
        this.balance = amount;
    }

    public void setid(int id) {
        this.id = id;
    }

    public int getid() {
        return id;
    }

    public double getBalance() {
        return balance;
    }

    public void setannualInterestRate(double annualInterestRate) {
        this.annualInterestRate = annualInterestRate;
    }

    public double getannualInterestRate() {
        return annualInterestRate;
    }

    public Date getdateCreated() {
        return dateCreated;
    }

    public void deposit(double amount) {
        balance += amount;
    }

    public void withdraw(double amount) {
        balance -= amount;
    }

    public double getMonthlyInterestRate() {
        return annualInterestRate / 12;
    }

    public double getMonthlyInterest() {
        return (balance * getMonthlyInterestRate()) / 100;
    }
}
