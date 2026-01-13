import math
from typing import Union, List

class MathUtils:
    """
    Custom math utilities.
    """
    
    @staticmethod
    def round(num: Union[float, int]) -> Union[float, int]:
        """
        JavaScript-compatible rounding.
        
        Args:
            num: Number to round
        
        Returns:
            Rounded number with same sign as input
        """
        x = math.floor(num)
        if (num - x) >= 0.5:
            x = math.ceil(num)
        return math.copysign(x, num)

    @staticmethod
    def interpolate_num(from_val: Union[float, int, bool], to_val: Union[float, int, bool], f: Union[float, int]) -> Union[float, int, bool]:
        """
        Interpolate between two numbers or booleans.
        
        Args:
            from_val: Starting value
            to_val: Ending value
            f: Interpolation factor (0.0 to 1.0)
        
        Returns:
            Interpolated value
        """
        if all([isinstance(number, (int, float)) for number in [from_val, to_val]]):
            return from_val * (1 - f) + to_val * f
        if all([isinstance(number, bool) for number in [from_val, to_val]]):
            return from_val if f < 0.5 else to_val
        return from_val

    @staticmethod
    def interpolate(from_list: List[Union[float, int]], to_list: List[Union[float, int]], f: Union[float, int]) -> List[Union[float, int]]:
        """
        Interpolate between two lists of values.
        
        Args:
            from_list: Starting list of values
            to_list: Ending list of values
            f: Interpolation factor (0.0 to 1.0)
        
        Returns:
            List of interpolated values
        
        Raises:
            ValueError: If input lists have different lengths
        """
        if len(from_list) != len(to_list):
            raise ValueError(f"Mismatched interpolation arguments {from_list}: {to_list}")
        return [MathUtils.interpolate_num(from_list[i], to_list[i], f) for i in range(len(from_list))]


    @staticmethod
    def convert_rotation_to_matrix(rotation: Union[float, int]) -> List[Union[float, int]]:
        """
        Convert rotation angle to transformation matrix.
        
        Args:
            rotation: Rotation angle in degrees
        
        Returns:
            List of 4 matrix values [cos, -sin, sin, cos]
        """
        rad = math.radians(rotation)
        return [math.cos(rad), -math.sin(rad), math.sin(rad), math.cos(rad)]


    @staticmethod
    def float_to_hex(x: Union[float, int]) -> str:
        """
        Convert float to hexadecimal string.
        
        Args:
            x: Float or integer value to convert
        
        Returns:
            Hexadecimal string representation
        """
        result = []
        quotient = int(x)
        fraction = x - quotient

        while quotient > 0:
            quotient = int(x / 16)
            remainder = int(x - (float(quotient) * 16))

            if remainder > 9:
                result.insert(0, chr(remainder + 55))
            else:
                result.insert(0, str(remainder))

            x = float(quotient)

        if fraction == 0:
            return ''.join(result)

        result.append('.')

        while fraction > 0:
            fraction *= 16
            integer = int(fraction)
            fraction -= float(integer)

            if integer > 9:
                result.append(chr(integer + 55))
            else:
                result.append(str(integer))

        return ''.join(result)


    @staticmethod
    def is_odd(num: Union[int, float]) -> float:
        """
        Check if number is odd and return corresponding value.
        
        Args:
            num: Number to check
        
        Returns:
            -1.0 if odd, 0.0 if even
        """
        if num % 2:
            return -1.0
        return 0.0

