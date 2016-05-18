package com.praetorian.burp;

import burp.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.net.URLEncoder;
import java.util.List;

/**
 * Tab to pretty print and edit parameters.
 */
public class JsonParameterDecoderTab extends BaseEditorTab implements IMessageEditorTab {
    static final String PARAMETER_NAME = "json";

    public JsonParameterDecoderTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks,
                                   IExtensionHelpers helpers, boolean editable) {
        super(controller, callbacks, helpers, editable);
    }

    @Override
    public String getTabCaption() {
        return String.format("%s Editor", PARAMETER_NAME);
    }

    @Override
    protected boolean detectConditions(byte[] content, boolean isRequest) {
        if (!isRequest) {
            return false;
        }

        List<IParameter> parameters = this.helpers.analyzeRequest(content).getParameters();
        for (IParameter p: parameters){
            if (p.getName().equals(PARAMETER_NAME)) {
                this.messageParameter = p;
                return true;
            }
        }
        return false;
    }

    @Override
    protected String formatData (String unformattedData) throws Exception {
        String formattedData;
        try {
            String uglyJSONString = this.helpers.urlDecode(unformattedData);
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            JsonParser jp = new JsonParser();
            JsonElement je = jp.parse(uglyJSONString);
            formattedData = gson.toJson(je);
        } catch (Exception e) {
            throw e;
        }
        return formattedData;
    }

    @Override
    protected String unformatData (String formattedData) throws Exception {
        String unformattedData;
        try {
            String json = this.helpers.bytesToString(this.txtInput.getText());
            json = json.trim().replaceAll("(\\s|\\n|\\t)", "");
            unformattedData = URLEncoder.encode(json, "UTF-8");
        } catch (Exception e) {
            throw e;
        }
        return unformattedData;
    }
}
