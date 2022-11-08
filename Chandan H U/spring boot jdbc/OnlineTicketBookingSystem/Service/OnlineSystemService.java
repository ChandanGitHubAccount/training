package example.OnlineTicketBookingSystem.Service;

import example.OnlineTicketBookingSystem.Model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
public class OnlineSystemService implements OnlineSystemInterface, CustomerToSystemInterface, SystemToCustomerInterface {

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Override
    public String generateCustomerId() {
        Random random = new Random();
        StringBuilder CustomerId = new StringBuilder();
        for (int index = 0; index < 4; index++) {
            char character = (char) (65 + random.nextInt(26));
            try {
                CustomerId.append(character);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        for (int index = 0; index < 6; index++) {
            char number = (char) (48 + random.nextInt(10));
            try {
                CustomerId.append(number);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        return CustomerId.toString();
    }

    @Override
    public int generatePaymentIdOrBookingId() {
        Random random = new Random();
        StringBuilder Id = new StringBuilder();
        for (int index = 0; index < 8; index++) {
            char number = (char) (48 + random.nextInt(10));
            try {
                Id.append(number);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        return Integer.parseInt(Id.toString());
    }

    @Override
    public List<Movie> showRunningMovieByName(String movieName, String customerId) {

        try {
            return jdbcTemplate.query("SELECT * FROM movie WHERE movieTitle = ?", new BeanPropertyRowMapper<>(Movie.class), movieName);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<Movie> showRunningMovieByLanguage(String movieLanguage) {
        try {
            return jdbcTemplate.query("SELECT * FROM movie WHERE movieLanguage = ?", new BeanPropertyRowMapper<>(Movie.class), movieLanguage);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<Movie> showRunningMovieByGenre(String movieGenre) {
        try {
            return jdbcTemplate.query("SELECT * FROM movie WHERE movieGenre = ?", new BeanPropertyRowMapper<>(Movie.class), movieGenre);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<Movie> showRunningMovieByCity(String city) {
        try {
            int length = 0;
            List<Screens> screensListForMovieId = jdbcTemplate.query("select  * from screens where theatreId in " +
                            "(select theatreId from theatre where cityId in (select cityId from city where cityName = ?))group by movieId",
                    new BeanPropertyRowMapper<>(Screens.class), city);
            String[] movieId = new String[screensListForMovieId.size()];
            List<Movie> movies = new ArrayList<>();
            for (Screens screens : screensListForMovieId) {
                movieId[length] = screens.getMovieId();
                length++;
            }
            for (String string : movieId) {
                List<Movie> movieList = jdbcTemplate.query("SELECT * FROM movie WHERE movieId = ?", new BeanPropertyRowMapper<>(Movie.class), string);
                movies.add(movieList.get(0));
            }
            return movies;
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public String getCustomerId(long phoneNumber, String eMail) {
        try {
            List<CustomerAccounts> customerAccount = jdbcTemplate.query("SELECT * FROM customerAccounts WHERE customerPhoneNumber = ? OR customerEmail = ?",
                    new BeanPropertyRowMapper<>(CustomerAccounts.class), phoneNumber, eMail);
            return customerAccount.get(0).getCustomerId();
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean verifyCustomerId(String customerId) {
        Integer customerAccountId = jdbcTemplate.queryForObject("SELECT count(*) FROM TABLE WHERE customerId = ? ",
                Integer.class, customerId);
        return customerAccountId == null;
    }

    @Override
    public boolean verifyBookingId(int bookingId) {
        Integer bookId = jdbcTemplate.queryForObject("SELECT count(*) FROM TABLE WHERE customerId = ? ",
                Integer.class, bookingId);
        return bookId == null;
    }

    @Override
    public List<ShowNames> viewAvailableShows() {
        try {
            return new ArrayList<>(EnumSet.allOf(ShowNames.class));
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<TypeOfPayment> typeOfPaymentAvailable() {
        try {
            return new ArrayList<>(EnumSet.allOf(TypeOfPayment.class));
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean verifyForEmptySeatAvailability(String theatreId) {
        Integer numberOfSeats = jdbcTemplate.queryForObject("SELECT maximumNumberOfSeats FROM screens WHERE theatreId = ?",
                Integer.class, theatreId);
        return numberOfSeats == null ? true : false;
    }

    @Override
    public List<CustomerAccounts> newCustomerRegistration(CustomerAccounts customerDetails) {
        try {
            String customerId = generateCustomerId();
            if (!verifyCustomerId(customerId))
                newCustomerRegistration(customerDetails);
            jdbcTemplate.update("INSERT INTO CustomerAccounts VALUES(?,?,?,?,?)",
                    customerId, customerDetails.getCustomerName(), customerDetails.getCustomerEmail(),
                    customerDetails.getCustomerPhoneNumber(), AccountStatus.ACTIVE.toString());
            return jdbcTemplate.query("SELECT * FROM customerAccounts WHERE customerId = ?",
                    new BeanPropertyRowMapper<>(CustomerAccounts.class), customerId);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<BookingStatusOfCustomer> bookingMovieTicket(BookingStatusOfCustomer statusOfCustomer) {
        if (verifyCustomerId(statusOfCustomer.getCustomerId())) {
            try {
                Integer numberOfSeats = jdbcTemplate.queryForObject("SELECT maximumNumberOfSeats FROM screens WHERE theatreId = ?",
                        Integer.class, statusOfCustomer.getTheatreId());
                if (numberOfSeats >= statusOfCustomer.getCurrentNumberOfSeatsBooked()) {
                    jdbcTemplate.update("INSERT INTO BookingStatusOfCustomer VALUES(?,?,?,?,?)", generatePaymentIdOrBookingId(),
                            statusOfCustomer.getCustomerId(), statusOfCustomer.getTheatreId(), statusOfCustomer.getShowName(),
                            statusOfCustomer.getCurrentNumberOfSeatsBooked());
                    return jdbcTemplate.query("SELECT * FROM BookingStatusOfCustomer WHERE CustomerId = ?",
                            new BeanPropertyRowMapper<>(BookingStatusOfCustomer.class), statusOfCustomer.getCustomerId());
                }
            } catch (Exception exception) {
                exception.printStackTrace();
                return null;
            }
        }
        return null;
    }

    @Override
    public List<CustomerPaymentDetails> makePaymentForBookedSeats(CustomerPaymentDetails paymentDetails) {

        Date currentDate = jdbcTemplate.queryForObject("SELECT CURDATE()", Date.class);
        Integer seats = jdbcTemplate.queryForObject("SELECT currentNumberOfSeatsBooked FROM BookingStatusOfCustomer WHERE bookingNumber = ?",
                Integer.class, paymentDetails.getBookingNumber());
        int numberOfSeats = seats == null ? 0 : seats;
        jdbcTemplate.update("INSERT INTO CustomerPaymentDetails VALUES(?,?,?,?,?,?)", generatePaymentIdOrBookingId(),
                paymentDetails.getBookingNumber(), paymentDetails.getPaymentType(), currentDate, numberOfSeats * 150, SeatStatus.CONFIRMED.toString());
        return null;
    }
}

