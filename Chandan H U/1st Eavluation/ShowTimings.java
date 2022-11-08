package FirstEavluation;

public enum ShowTimings {
    FIRSTSHOWTIMING {
        public String toString() {
            return "FIRSTSHOWTIMING - 9:30 TO 12:15";
        }
    }, SECONDSHOWTIMING {
        public String toString() {
            return "SECONDSHOWTIMING - 12:45 to 3:15";
        }
    }, THIRDSHOWTIMING {
        public String toString() {
            return "THIRDSHOWTIMING - 3:45 to 6:30";
        }
    }, NIGTHSHOWTIMING {
        public String toString() {
            return "NIGTHSHOWTIMING - 7:15 to 11";
        }
    }


}
