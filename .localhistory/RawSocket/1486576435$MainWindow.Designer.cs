namespace RawSocket
{
    partial class MainWindow
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.buttonSendStop = new System.Windows.Forms.Button();
            this.buttonSend = new System.Windows.Forms.Button();
            this.groupBoxServer = new System.Windows.Forms.GroupBox();
            this.textBoxServerStatus = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.numericUpDownServerPort = new System.Windows.Forms.NumericUpDown();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.comboBoxServerAddress = new System.Windows.Forms.ComboBox();
            this.ListenStop = new System.Windows.Forms.Button();
            this.buttonListen = new System.Windows.Forms.Button();
            this.textBoxDebug = new System.Windows.Forms.TextBox();
            this.groupBoxClient = new System.Windows.Forms.GroupBox();
            this.textBoxClientStatus = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.numericUpDownClientPort = new System.Windows.Forms.NumericUpDown();
            this.label5 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.comboBoxClientAddress = new System.Windows.Forms.ComboBox();
            this.buttonPlus = new System.Windows.Forms.Button();
            this.checkBoxServer = new System.Windows.Forms.CheckBox();
            this.checkBoxClient = new System.Windows.Forms.CheckBox();
            this.comboBoxMethod = new System.Windows.Forms.ComboBox();
            this.groupBoxMethod = new System.Windows.Forms.GroupBox();
            this.buttonSteganogr = new System.Windows.Forms.Button();
            this.textBoxSecret = new System.Windows.Forms.TextBox();
            this.label7 = new System.Windows.Forms.Label();
            this.groupBoxServer.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownServerPort)).BeginInit();
            this.groupBoxClient.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownClientPort)).BeginInit();
            this.groupBoxMethod.SuspendLayout();
            this.SuspendLayout();
            // 
            // buttonSendStop
            // 
            this.buttonSendStop.Location = new System.Drawing.Point(223, 14);
            this.buttonSendStop.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.buttonSendStop.Name = "buttonSendStop";
            this.buttonSendStop.Size = new System.Drawing.Size(120, 28);
            this.buttonSendStop.TabIndex = 1;
            this.buttonSendStop.Text = "Stop";
            this.buttonSendStop.UseVisualStyleBackColor = true;
            this.buttonSendStop.Click += new System.EventHandler(this.buttonSendStop_Click);
            // 
            // buttonSend
            // 
            this.buttonSend.Location = new System.Drawing.Point(84, 14);
            this.buttonSend.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.buttonSend.Name = "buttonSend";
            this.buttonSend.Size = new System.Drawing.Size(120, 28);
            this.buttonSend.TabIndex = 0;
            this.buttonSend.Text = "Connect";
            this.buttonSend.UseVisualStyleBackColor = true;
            this.buttonSend.Click += new System.EventHandler(this.buttonSend_Click);
            // 
            // groupBoxServer
            // 
            this.groupBoxServer.Controls.Add(this.textBoxServerStatus);
            this.groupBoxServer.Controls.Add(this.label3);
            this.groupBoxServer.Controls.Add(this.ListenStop);
            this.groupBoxServer.Controls.Add(this.buttonListen);
            this.groupBoxServer.Location = new System.Drawing.Point(16, 114);
            this.groupBoxServer.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBoxServer.Name = "groupBoxServer";
            this.groupBoxServer.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBoxServer.Size = new System.Drawing.Size(359, 86);
            this.groupBoxServer.TabIndex = 1;
            this.groupBoxServer.TabStop = false;
            this.groupBoxServer.Text = "Server";
            // 
            // textBoxServerStatus
            // 
            this.textBoxServerStatus.Location = new System.Drawing.Point(78, 59);
            this.textBoxServerStatus.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.textBoxServerStatus.Name = "textBoxServerStatus";
            this.textBoxServerStatus.ReadOnly = true;
            this.textBoxServerStatus.Size = new System.Drawing.Size(265, 22);
            this.textBoxServerStatus.TabIndex = 8;
            this.textBoxServerStatus.Text = "not connected";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(24, 63);
            this.label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(46, 17);
            this.label3.TabIndex = 7;
            this.label3.Text = "status";
            // 
            // numericUpDownServerPort
            // 
            this.numericUpDownServerPort.Location = new System.Drawing.Point(94, 84);
            this.numericUpDownServerPort.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.numericUpDownServerPort.Maximum = new decimal(new int[] {
            65535,
            0,
            0,
            0});
            this.numericUpDownServerPort.Name = "numericUpDownServerPort";
            this.numericUpDownServerPort.Size = new System.Drawing.Size(267, 22);
            this.numericUpDownServerPort.TabIndex = 5;
            this.numericUpDownServerPort.Value = new decimal(new int[] {
            11000,
            0,
            0,
            0});
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(33, 87);
            this.label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(53, 17);
            this.label2.TabIndex = 4;
            this.label2.Text = "on port";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(25, 55);
            this.label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(61, 17);
            this.label1.TabIndex = 3;
            this.label1.Text = "listen on";
            // 
            // comboBoxServerAddress
            // 
            this.comboBoxServerAddress.FormattingEnabled = true;
            this.comboBoxServerAddress.Location = new System.Drawing.Point(94, 51);
            this.comboBoxServerAddress.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.comboBoxServerAddress.Name = "comboBoxServerAddress";
            this.comboBoxServerAddress.Size = new System.Drawing.Size(267, 24);
            this.comboBoxServerAddress.TabIndex = 2;
            // 
            // ListenStop
            // 
            this.ListenStop.Location = new System.Drawing.Point(225, 23);
            this.ListenStop.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.ListenStop.Name = "ListenStop";
            this.ListenStop.Size = new System.Drawing.Size(120, 28);
            this.ListenStop.TabIndex = 1;
            this.ListenStop.Text = "Disconnect";
            this.ListenStop.UseVisualStyleBackColor = true;
            this.ListenStop.Click += new System.EventHandler(this.ListenStop_Click);
            // 
            // buttonListen
            // 
            this.buttonListen.Location = new System.Drawing.Point(78, 23);
            this.buttonListen.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.buttonListen.Name = "buttonListen";
            this.buttonListen.Size = new System.Drawing.Size(120, 28);
            this.buttonListen.TabIndex = 0;
            this.buttonListen.Text = "Listen";
            this.buttonListen.UseVisualStyleBackColor = true;
            this.buttonListen.Click += new System.EventHandler(this.buttonListen_Click);
            // 
            // textBoxDebug
            // 
            this.textBoxDebug.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.textBoxDebug.Location = new System.Drawing.Point(742, 15);
            this.textBoxDebug.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.textBoxDebug.Multiline = true;
            this.textBoxDebug.Name = "textBoxDebug";
            this.textBoxDebug.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.textBoxDebug.Size = new System.Drawing.Size(663, 377);
            this.textBoxDebug.TabIndex = 2;
            // 
            // groupBoxClient
            // 
            this.groupBoxClient.Controls.Add(this.textBoxClientStatus);
            this.groupBoxClient.Controls.Add(this.buttonSendStop);
            this.groupBoxClient.Controls.Add(this.label4);
            this.groupBoxClient.Controls.Add(this.buttonSend);
            this.groupBoxClient.Location = new System.Drawing.Point(383, 114);
            this.groupBoxClient.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBoxClient.Name = "groupBoxClient";
            this.groupBoxClient.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBoxClient.Size = new System.Drawing.Size(349, 86);
            this.groupBoxClient.TabIndex = 9;
            this.groupBoxClient.TabStop = false;
            this.groupBoxClient.Text = "Client";
            // 
            // textBoxClientStatus
            // 
            this.textBoxClientStatus.Location = new System.Drawing.Point(84, 46);
            this.textBoxClientStatus.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.textBoxClientStatus.Name = "textBoxClientStatus";
            this.textBoxClientStatus.ReadOnly = true;
            this.textBoxClientStatus.Size = new System.Drawing.Size(259, 22);
            this.textBoxClientStatus.TabIndex = 8;
            this.textBoxClientStatus.Text = "not connected";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(30, 49);
            this.label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(46, 17);
            this.label4.TabIndex = 7;
            this.label4.Text = "status";
            // 
            // numericUpDownClientPort
            // 
            this.numericUpDownClientPort.Location = new System.Drawing.Point(459, 84);
            this.numericUpDownClientPort.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.numericUpDownClientPort.Maximum = new decimal(new int[] {
            65535,
            0,
            0,
            0});
            this.numericUpDownClientPort.Name = "numericUpDownClientPort";
            this.numericUpDownClientPort.Size = new System.Drawing.Size(267, 22);
            this.numericUpDownClientPort.TabIndex = 5;
            this.numericUpDownClientPort.Value = new decimal(new int[] {
            11000,
            0,
            0,
            0});
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(404, 87);
            this.label5.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(49, 17);
            this.label5.TabIndex = 4;
            this.label5.Text = "to port";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(383, 55);
            this.label6.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(71, 17);
            this.label6.TabIndex = 3;
            this.label6.Text = "send from";
            // 
            // comboBoxClientAddress
            // 
            this.comboBoxClientAddress.FormattingEnabled = true;
            this.comboBoxClientAddress.Location = new System.Drawing.Point(459, 51);
            this.comboBoxClientAddress.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.comboBoxClientAddress.Name = "comboBoxClientAddress";
            this.comboBoxClientAddress.Size = new System.Drawing.Size(267, 24);
            this.comboBoxClientAddress.TabIndex = 2;
            // 
            // buttonPlus
            // 
            this.buttonPlus.Location = new System.Drawing.Point(708, 15);
            this.buttonPlus.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.buttonPlus.Name = "buttonPlus";
            this.buttonPlus.Size = new System.Drawing.Size(31, 28);
            this.buttonPlus.TabIndex = 10;
            this.buttonPlus.Text = "+";
            this.buttonPlus.UseVisualStyleBackColor = true;
            this.buttonPlus.Click += new System.EventHandler(this.buttonPlus_Click);
            // 
            // checkBoxServer
            // 
            this.checkBoxServer.AutoSize = true;
            this.checkBoxServer.CheckAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.checkBoxServer.Location = new System.Drawing.Point(303, 15);
            this.checkBoxServer.Name = "checkBoxServer";
            this.checkBoxServer.Size = new System.Drawing.Size(72, 21);
            this.checkBoxServer.TabIndex = 11;
            this.checkBoxServer.Text = "Server";
            this.checkBoxServer.UseVisualStyleBackColor = true;
            this.checkBoxServer.CheckedChanged += new System.EventHandler(this.checkBoxServer_CheckedChanged);
            // 
            // checkBoxClient
            // 
            this.checkBoxClient.AutoSize = true;
            this.checkBoxClient.Location = new System.Drawing.Point(383, 15);
            this.checkBoxClient.Name = "checkBoxClient";
            this.checkBoxClient.Size = new System.Drawing.Size(65, 21);
            this.checkBoxClient.TabIndex = 12;
            this.checkBoxClient.Text = "Client";
            this.checkBoxClient.UseVisualStyleBackColor = true;
            this.checkBoxClient.CheckedChanged += new System.EventHandler(this.checkBoxClient_CheckedChanged);
            // 
            // comboBoxMethod
            // 
            this.comboBoxMethod.FormattingEnabled = true;
            this.comboBoxMethod.Items.AddRange(new object[] {
            "FTP transfer",
            "Byte transfer"});
            this.comboBoxMethod.Location = new System.Drawing.Point(374, 21);
            this.comboBoxMethod.Name = "comboBoxMethod";
            this.comboBoxMethod.Size = new System.Drawing.Size(336, 24);
            this.comboBoxMethod.TabIndex = 13;
            // 
            // groupBoxMethod
            // 
            this.groupBoxMethod.Controls.Add(this.buttonSteganogr);
            this.groupBoxMethod.Controls.Add(this.comboBoxMethod);
            this.groupBoxMethod.Controls.Add(this.textBoxSecret);
            this.groupBoxMethod.Controls.Add(this.label7);
            this.groupBoxMethod.Location = new System.Drawing.Point(16, 207);
            this.groupBoxMethod.Name = "groupBoxMethod";
            this.groupBoxMethod.Size = new System.Drawing.Size(716, 185);
            this.groupBoxMethod.TabIndex = 14;
            this.groupBoxMethod.TabStop = false;
            this.groupBoxMethod.Text = "Method";
            // 
            // buttonSteganogr
            // 
            this.buttonSteganogr.Location = new System.Drawing.Point(598, 146);
            this.buttonSteganogr.Name = "buttonSteganogr";
            this.buttonSteganogr.Size = new System.Drawing.Size(112, 28);
            this.buttonSteganogr.TabIndex = 14;
            this.buttonSteganogr.Text = "Send / receive";
            this.buttonSteganogr.UseVisualStyleBackColor = true;
            this.buttonSteganogr.Click += new System.EventHandler(this.buttonSteganogr_Click);
            // 
            // textBoxSecret
            // 
            this.textBoxSecret.Location = new System.Drawing.Point(6, 68);
            this.textBoxSecret.Multiline = true;
            this.textBoxSecret.Name = "textBoxSecret";
            this.textBoxSecret.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.textBoxSecret.Size = new System.Drawing.Size(704, 72);
            this.textBoxSecret.TabIndex = 15;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(3, 48);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(118, 17);
            this.label7.TabIndex = 16;
            this.label7.Text = "Secret to transfer";
            // 
            // MainWindow
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1423, 405);
            this.Controls.Add(this.groupBoxMethod);
            this.Controls.Add(this.checkBoxClient);
            this.Controls.Add(this.numericUpDownServerPort);
            this.Controls.Add(this.checkBoxServer);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.numericUpDownClientPort);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.buttonPlus);
            this.Controls.Add(this.comboBoxServerAddress);
            this.Controls.Add(this.groupBoxClient);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.textBoxDebug);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.groupBoxServer);
            this.Controls.Add(this.comboBoxClientAddress);
            this.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.Name = "MainWindow";
            this.Text = "Communication";
            this.groupBoxServer.ResumeLayout(false);
            this.groupBoxServer.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownServerPort)).EndInit();
            this.groupBoxClient.ResumeLayout(false);
            this.groupBoxClient.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownClientPort)).EndInit();
            this.groupBoxMethod.ResumeLayout(false);
            this.groupBoxMethod.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Button buttonSend;
        private System.Windows.Forms.GroupBox groupBoxServer;
        private System.Windows.Forms.Button buttonListen;
        private System.Windows.Forms.TextBox textBoxDebug;
        private System.Windows.Forms.Button buttonSendStop;
        private System.Windows.Forms.Button ListenStop;
        private System.Windows.Forms.NumericUpDown numericUpDownServerPort;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox textBoxServerStatus;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.GroupBox groupBoxClient;
        private System.Windows.Forms.TextBox textBoxClientStatus;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.NumericUpDown numericUpDownClientPort;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.ComboBox comboBoxClientAddress;
        private System.Windows.Forms.Button buttonPlus;
        private System.Windows.Forms.CheckBox checkBoxServer;
        private System.Windows.Forms.CheckBox checkBoxClient;
        private System.Windows.Forms.ComboBox comboBoxMethod;
        private System.Windows.Forms.GroupBox groupBoxMethod;
        private System.Windows.Forms.Button buttonSteganogr;
        private System.Windows.Forms.TextBox textBoxSecret;
        private System.Windows.Forms.Label label7;
        public System.Windows.Forms.ComboBox comboBoxServerAddress;
    }
}

