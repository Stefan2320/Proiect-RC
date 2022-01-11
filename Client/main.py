from PyQt5.QtWidgets import QApplication, QDialog
from interface import *
from functions import palette_theme
import sys

if __name__ == '__main__':
    app = QApplication([])

    dialog = QDialog()
    myWindow = MainWindow(dialog)

    widget = QtWidgets.QStackedWidget()
    widget.addWidget(dialog)
    widget.resize(640,755)
    widget.setWindowTitle("CoAP Client")
    widget.show()

    app.setPalette(palette_theme())

    sys.exit(app.exec_())