import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;

/**
 * Created by Will on 1/29/2017.
 */
public class Driver
{
    public static CardInfo find_start(DataInputStream stream)
    {
        try
        {
            while (true)
            {
                int b = stream.readUnsignedByte();
                if (b == 37 && stream.readUnsignedByte() == 66) // byte for '%' character and 'B' character
                {
                    CardInfo info = parse_data(stream);
                    if (info != null)
                    {
                        return info;
                    }
                }
            }
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static Integer parse_digit(int b)
    {
        if (b >= 48 && b <= 57)
        {
            return b - 48;
        }
        else
        {
            return null;
        }
    }

    public static String parse_number(DataInputStream stream, int length) throws Exception
    {
        String result = "";
        for (int i = 0; i < length; ++i)
        {
            int b = stream.readUnsignedByte();
            Integer digit = parse_digit(b);
            if (digit == null)
            {
                return null;
            }

            result += digit;
        }

        return result;
    }

    public static Character parse_character(int b)
    {
        if (b >= 65 && b <= 91)
        {
            return (char)b;
        }
        else if (b >= 97 && b <= 133)
        {
            return (char)b;
        }
        else
        {
            return null;
        }
    }

    public static CardInfo parse_data(DataInputStream stream)
    {
        CardInfo info = new CardInfo();

        try
        {
            // Keep track of last byte read
            int b;

            // Read the credit card number
            while (true)
            {
                b = stream.readUnsignedByte();
                Integer digit = parse_digit(b);
                if (digit != null)
                {
                    info.card_number += digit;
                }
                else
                {
                    break;
                }
            }

            // Make sure the credit card number is the correct length
            if (info.card_number.length() < 13 || info.card_number.length() > 19)
            {
                return null;
            }

            // Read the name
            if (b != 94)
            {
                return null;
            }

            // Read the first name
            while (true)
            {
                b = stream.readUnsignedByte();

                // Get the letter
                Character letter = parse_character(b);
                if (letter != null)
                {
                    info.name += letter;
                }
                else
                {
                    break;
                }
            }

            // If it's the slash
            if (b == 47)
            {
                info.name += ' ';
            }
            else
            {
                return null;
            }

            // Read the last name
            while (true)
            {
                b = stream.readUnsignedByte();

                // Get the letter
                Character letter = parse_character(b);
                if (letter != null)
                {
                    info.name += letter;
                }
                else
                {
                    break;
                }
            }

            // Make sure the final character was the carrot
            if (b != 94)
            {
                return null;
            }

            // Verify name length
            if (info.name.length() <= 2 && info.name.length() >= 26)
            {
                return null;
            }

            // Read expiration year
            info.expiration_year = parse_number(stream, 2);
            if (info.expiration_year == null)
            {
                return null;
            }

            // Read expiration year
            info.expiration_month = parse_number(stream, 2);
            if (info.expiration_month == null)
            {
                return null;
            }

            // Read service code
            info.service_code = parse_number(stream, 3);
            if (info.service_code == null)
            {
                return null;
            }

            // Read discretionary data
            while (true)
            {
                b = stream.readUnsignedByte();
                Integer digit = parse_digit(b);
                if (digit == null)
                {
                    break;
                }

                info.discretionary_data += digit;
            }

            // Make sure the last character was a question mark
            if (b != 63)
            {
                return null;
            }

            // Make sure the next character is a semicolon
            b = stream.readUnsignedByte();
            if (b != 59)
            {
                return null;
            }

            // Verify that the track two card number is correct
            String track_2_number = parse_number(stream, info.card_number.length());
            if (track_2_number == null || !track_2_number.equals(info.card_number))
            {
                return null;
            }

            // Verify that the next character is an equals sign
            b = stream.readUnsignedByte();
            if (b != 61)
            {
                return null;
            }

            // Verify that the track two expiration year is correct
            String track_2_exp_year = parse_number(stream, 2);
            if (track_2_exp_year == null || !track_2_exp_year.equals(info.expiration_year))
            {
                return null;
            }

            // Verify that the track two expiration month is correct
            String track_2_exp_month = parse_number(stream, 2);
            if (track_2_exp_month == null || !track_2_exp_month.equals(info.expiration_month))
            {
                return null;
            }

            // Verify that the service code is correct
            String track_2_service_code = parse_number(stream, 3);
            if (track_2_service_code == null || !track_2_service_code.equals(info.service_code))
            {
                return null;
            }

            // Get the pin
            info.pin = parse_number(stream, 4);
            if (info.pin == null)
            {
                return null;
            }

            // Get the ccv
            info.ccv = parse_number(stream, 3);
            if (info.ccv == null)
            {
                return null;
            }
        }
        catch (Exception e)
        {
            return null;
        }

        return info;
    }

    public static void main(String[] args)
    {
        try
        {
            FileInputStream file = new FileInputStream(new File("memorydump.dmp"));
            DataInputStream data_stream = new DataInputStream(new BufferedInputStream(file));

            while (true)
            {
                CardInfo info = find_start(data_stream);
                if (info == null)
                {
                    return;
                }

                System.out.println("Card number: " + info.card_number);
                System.out.println("Cardholder: " + info.name);
                System.out.println("Exp Year: " + info.expiration_year);
                System.out.println("Exp month: " + info.expiration_month);
                System.out.println("Service Code: " + info.service_code);
                System.out.println("Pin: " + info.pin);
                System.out.println("CCV: " + info.ccv);
            }
    }
        catch (Exception e)
        {

        }
    }
}
