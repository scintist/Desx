import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DESXApp extends Application {

    private TextField keyField;
    private TextArea inputArea;
    private TextArea outputArea;
    private Stage primaryStage;

    @Override
    public void start(Stage stage) {
        this.primaryStage = stage;
        stage.setTitle("Szyfrowanie DESX");

        VBox root = new VBox(15);
        root.setPadding(new Insets(20));

        HBox keyBox = new HBox(10);
        keyBox.setAlignment(Pos.CENTER_LEFT);
        Label keyLabel = new Label("Klucz (24 znaki):");
        keyField = new TextField("123456789012345678901234");
        keyField.setPrefWidth(250);
        keyBox.getChildren().addAll(keyLabel, keyField);

        Label inputLabel = new Label("Tekst wejściowy:");
        inputArea = new TextArea();
        inputArea.setPrefRowCount(5);

        Label outputLabel = new Label("Wynik:");
        outputArea = new TextArea();
        outputArea.setEditable(false);
        outputArea.setPrefRowCount(5);

        HBox buttonsBox = new HBox(15);
        buttonsBox.setAlignment(Pos.CENTER);

        Button btnEncryptText = new Button("Szyfruj Tekst");
        Button btnDecryptText = new Button("Deszyfruj Tekst");
        Button btnEncryptFile = new Button("Szyfruj Plik");
        Button btnDecryptFile = new Button("Deszyfruj Plik");

        buttonsBox.getChildren().addAll(btnEncryptText, btnDecryptText, btnEncryptFile, btnDecryptFile);

        btnEncryptText.setOnAction(e -> processText(true));
        btnDecryptText.setOnAction(e -> processText(false));

        root.getChildren().addAll(
                keyBox,
                inputLabel,
                inputArea,
                outputLabel,
                outputArea,
                buttonsBox
        );

        Scene scene = new Scene(root, 700, 500);
        stage.setScene(scene);
        stage.show();
    }

    private void processText(boolean encrypt) {
        try {
            byte[] key = getKey();
            if (encrypt) {
                byte[] input = inputArea.getText().getBytes(StandardCharsets.UTF_8);
                byte[] output = DESX.process(input, key, true);
                outputArea.setText(Base64.getEncoder().encodeToString(output));
            } else {
                byte[] input = Base64.getDecoder().decode(inputArea.getText());
                byte[] output = DESX.process(input, key, false);
                outputArea.setText(new String(output, StandardCharsets.UTF_8));
            }
        } catch (Exception ex) {
            showAlert("Błąd podczas przetwarzania tekstu", ex.getMessage(), Alert.AlertType.ERROR);
        }
    }

    private byte[] getKey() throws Exception {
        byte[] key = keyField.getText().getBytes(StandardCharsets.UTF_8);
        if (key.length != 24) {
            throw new Exception("Klucz musi składać się z dokładnie 24 bajtów.");
        }
        return key;
    }

    private void showAlert(String title, String content, Alert.AlertType type) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}