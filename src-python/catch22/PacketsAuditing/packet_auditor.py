import os

import imageio.v3 as iio

RGB_GREEN = [0, 133, 71]
RGB_ORANGE = [242, 121, 48]

for dir_path, dirs, files in os.walk(r'c:\Users\vernj\Downloads'):
    for filename in files:
        file_path = os.path.join(dir_path, filename)

        img = iio.imread(file_path)

        bg_color = img[0][0].tolist()
        package_color = img[125][125].tolist()

        if bg_color == RGB_ORANGE and package_color == RGB_GREEN:
            print(file_path)
