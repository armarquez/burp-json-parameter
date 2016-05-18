package burp;

import com.praetorian.burp.JsonParameterDecoderTab;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {
	static final String NAME = "JSON Parameter Decoder";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

		callbacks.setExtensionName(NAME);

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.helpers = callbacks.getHelpers();

        // register Aura message tab
        this.callbacks.registerMessageEditorTabFactory(new IMessageEditorTabFactory() {
            @Override
            public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
                return new JsonParameterDecoderTab(controller, callbacks, helpers, editable);
            }
        });
	}
}
