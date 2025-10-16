import sys, traceback, logging
from PyQt5 import QtWidgets
from gui import MainWindow

logging.basicConfig(filename='app_error.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

def excepthook(exc_type, exc_value, exc_tb):
    logging.error("Uncaught", exc_info=(exc_type, exc_value, exc_tb))
    traceback.print_exception(exc_type, exc_value, exc_tb)
    try:
        QtWidgets.QMessageBox.critical(None, "Fatal error",
                                       "Unexpected error. See app_error.log for details.")
    except Exception:
        pass
    sys.exit(1)

sys.excepthook = excepthook

def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
