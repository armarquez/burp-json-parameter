package com.praetorian.burp;

import burp.*;

import java.awt.*;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Base class for editor tabs.
 */
public abstract class BaseEditorTab implements IMessageEditorTab {
    protected static PrintStream stderr;
    protected static PrintStream stdout;

    protected IBurpExtenderCallbacks callbacks;
    protected IExtensionHelpers helpers;
    protected boolean editable;
    protected ITextEditor txtInput;
    protected byte[] currentMessage;

    protected IParameter messageParameter;

    public BaseEditorTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks,
                         IExtensionHelpers helpers, boolean editable) {

        this.callbacks = callbacks;
        this.helpers = helpers;
        this.editable = editable;

        this.txtInput = callbacks.createTextEditor();
        this.txtInput.setEditable(editable);
    }

    /**
     * Formats data from an HTTP request or response value.
     *
     * @param unformattedData	HTTP request or response value containing the the unformatted data.
     * @return 					the formatted data.
     * @throws Exception		in case formatting failed.
     */
    protected abstract String formatData (String unformattedData) throws Exception;

    /**
     * Unformats data from an HTTP request or response value.
     *
     * @param formattedData	    Data that needs to be have formatting stripped.
     * @return					the data with formatting removed.
     * @throws Exception		in case removing of the data formatting failed.
     */
    protected abstract String unformatData (String formattedData) throws Exception;

    /**
     * Returns whether a certain conditions have been detected.
     *
     * @param content			Analyze this content.
     * @param isRequest         states whether the content is from a request or response.
     * @return					<code>true</code> if certain conditions are detected.
     */
    protected abstract boolean detectConditions (byte[] content, boolean isRequest);


    @Override
    public String getTabCaption() {
        return "Base Editor";
    }

    @Override
    public Component getUiComponent() {
        return txtInput.getComponent();
    }

    @Override
    public boolean isModified() {
        return this.txtInput.isTextModified();
    }

    @Override
    public byte[] getSelectedData() {
        return this.txtInput.getSelectedText();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return detectConditions(content, isRequest);
    }

    @Override
    public byte[] getMessage() {
        byte[] message = this.currentMessage;

        // reformat and URL encode text unless it is unchanged
        if (this.txtInput.isTextModified() && this.messageParameter != null) {
            try {
                String jsonString = this.helpers.bytesToString(this.txtInput.getText());
                IParameter updatedParameter = this.helpers.buildParameter(this.messageParameter.getName(),
                        unformatData(jsonString), this.messageParameter.getType());

                message = this.helpers.updateParameter(message, updatedParameter);
            } catch (Exception e) {
                Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, e);
                this.stderr.println(getStackTrace(e));
            }
        }

        return message;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (content == null) {
            // clear the editor
            this.txtInput.setText(null);
            this.txtInput.setEditable(false);
        } else {
            try {
                String formattedString = formatData(this.messageParameter.getValue());

                this.txtInput.setText(this.helpers.stringToBytes(formattedString));
                this.txtInput.setEditable(this.editable);
            } catch (Exception e) {
                Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, e);
                this.txtInput.setText(this.helpers.stringToBytes("\n--- FAILURE ---\n\nSee output in extension tab for details"));
                this.txtInput.setEditable(false);
                stderr.println(getStackTrace(e));
            }
        }

        // remember the currently displayed content
        this.currentMessage = content;
    }

    protected static String getStackTrace(Throwable t) {
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter, true);
        t.printStackTrace(printWriter);
        printWriter.flush();
        stringWriter.flush();

        return stringWriter.toString();
    }
}
