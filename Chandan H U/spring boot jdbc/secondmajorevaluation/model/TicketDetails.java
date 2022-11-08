package example.secondmajorevaluation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TicketDetails {
    private int ticketId,numberOfSeats,TicketAmount,passengerId,trainNumber,waitingId;
    private String coachType,trainDestination,trainStartingPoint,ticketStatus;
    private LocalDate bookedDate;
}
