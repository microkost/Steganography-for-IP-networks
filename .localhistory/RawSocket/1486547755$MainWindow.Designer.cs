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
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.textBoxServerStatus = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.numericUpDownServerPort = new System.Windows.Forms.NumericUpDown();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.comboBoxServerAddress = new System.Windows.Forms.ComboBox();
            this.ListenStop = new System.Windows.Forms.Button();
            this.buttonListen = new System.Windows.Forms.Button();
            this.textBoxDebug = new System.Windows.Forms.TextBox();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.textBoxClientStatus = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.numericUpDownClientPort = new System.Windows.Forms.NumericUpDown();
            this.label5 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.comboBoxClientAddress = new System.Windows.Forms.ComboBox();
            this.buttonPlus = new System.Windows.Forms.Button();
            this.checkBoxServer = new System.Windows.Forms.CheckBox();
            this.checkBoxClient = new System.Windows.Forms.CheckBox();
            this.groupBox2.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownServerPort)).BeginInit();
            this.groupBox1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownClientPort)).BeginInit();
            this.SuspendLayout();
            // 
            // buttonSendStop
            // 
            this.buttonSendStop.Location = new System.Drawing.Point(231, 81);
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
            this.buttonSend.Location = new System.Drawing.Point(84, 81);
            this.buttonSend.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.buttonSend.Name = "buttonSend";
            this.buttonSend.Size = new System.Drawing.Size(120, 28);
            this.buttonSend.TabIndex = 0;
            this.buttonSend.Text = "Connect";
            this.buttonSend.UseVisualStyleBackColor = true;
            this.buttonSend.Click += new System.EventHandler(this.buttonSend_Click);
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.textBoxServerStatus);
            this.groupBox2.Controls.Add(this.label3);
            this.groupBox2.Controls.Add(this.numericUpDownServerPort);
            this.groupBox2.Controls.Add(this.label2);
            this.groupBox2.Controls.Add(this.label1);
            this.groupBox2.Controls.Add(this.comboBoxServerAddress);
            this.groupBox2.Controls.Add(this.ListenStop);
            this.groupBox2.Controls.Add(this.buttonListen);
            this.groupBox2.Location = new System.Drawing.Point(16, 47);
            this.groupBox2.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBox2.Size = new System.Drawing.Size(359, 153);
            this.groupBox2.TabIndex = 1;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Server";
            // 
            // textBoxServerStatus
            // 
            this.textBoxServerStatus.Location = new System.Drawing.Point(77, 117);
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
            this.label3.Location = new System.Drawing.Point(23, 121);
            this.label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(46, 17);
            this.label3.TabIndex = 7;
            this.label3.Text = "status";
            // 
            // numericUpDownServerPort
            // 
            this.numericUpDownServerPort.Location = new System.Drawing.Point(77, 49);
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
            this.label2.Location = new System.Drawing.Point(16, 52);
            this.label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(53, 17);
            this.label2.TabIndex = 4;
            this.label2.Text = "on port";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(8, 20);
            this.label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(61, 17);
            this.label1.TabIndex = 3;
            this.label1.Text = "listen on";
            // 
            // comboBoxServerAddress
            // 
            this.comboBoxServerAddress.FormattingEnabled = true;
            this.comboBoxServerAddress.Location = new System.Drawing.Point(77, 16);
            this.comboBoxServerAddress.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.comboBoxServerAddress.Name = "comboBoxServerAddress";
            this.comboBoxServerAddress.Size = new System.Drawing.Size(265, 24);
            this.comboBoxServerAddress.TabIndex = 2;
            // 
            // ListenStop
            // 
            this.ListenStop.Location = new System.Drawing.Point(224, 81);
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
            this.buttonListen.Location = new System.Drawing.Point(77, 81);
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
            this.textBoxDebug.Location = new System.Drawing.Point(16, 207);
            this.textBoxDebug.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.textBoxDebug.Multiline = true;
            this.textBoxDebug.Name = "textBoxDebug";
            this.textBoxDebug.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.textBoxDebug.Size = new System.Drawing.Size(724, 402);
            this.textBoxDebug.TabIndex = 2;
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.textBoxClientStatus);
            this.groupBox1.Controls.Add(this.buttonSendStop);
            this.groupBox1.Controls.Add(this.label4);
            this.groupBox1.Controls.Add(this.numericUpDownClientPort);
            this.groupBox1.Controls.Add(this.buttonSend);
            this.groupBox1.Controls.Add(this.label5);
            this.groupBox1.Controls.Add(this.label6);
            this.groupBox1.Controls.Add(this.comboBoxClientAddress);
            this.groupBox1.Location = new System.Drawing.Point(383, 47);
            this.groupBox1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBox1.Size = new System.Drawing.Size(359, 153);
            this.groupBox1.TabIndex = 9;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Client";
            // 
            // textBoxClientStatus
            // 
            this.textBoxClientStatus.Location = new System.Drawing.Point(84, 117);
            this.textBoxClientStatus.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.textBoxClientStatus.Name = "textBoxClientStatus";
            this.textBoxClientStatus.ReadOnly = true;
            this.textBoxClientStatus.Size = new System.Drawing.Size(265, 22);
            this.textBoxClientStatus.TabIndex = 8;
            this.textBoxClientStatus.Text = "not connected";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(29, 121);
            this.label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(46, 17);
            this.label4.TabIndex = 7;
            this.label4.Text = "status";
            // 
            // numericUpDownClientPort
            // 
            this.numericUpDownClientPort.Location = new System.Drawing.Point(84, 49);
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
            this.label5.Location = new System.Drawing.Point(29, 52);
            this.label5.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(49, 17);
            this.label5.TabIndex = 4;
            this.label5.Text = "to port";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(8, 20);
            this.label6.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(71, 17);
            this.label6.TabIndex = 3;
            this.label6.Text = "send from";
            // 
            // comboBoxClientAddress
            // 
            this.comboBoxClientAddress.FormattingEnabled = true;
            this.comboBoxClientAddress.Location = new System.Drawing.Point(84, 16);
            this.comboBoxClientAddress.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.comboBoxClientAddress.Name = "comboBoxClientAddress";
            this.comboBoxClientAddress.Size = new System.Drawing.Size(265, 24);
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
            // 
            // MainWindow
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(751, 624);
            this.Controls.Add(this.checkBoxClient);
            this.Controls.Add(this.checkBoxServer);
            this.Controls.Add(this.buttonPlus);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.textBoxDebug);
            this.Controls.Add(this.groupBox2);
            this.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.Name = "MainWindow";
            this.Text = "Communication";
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownServerPort)).EndInit();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownClientPort)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Button buttonSend;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.Button buttonListen;
        private System.Windows.Forms.TextBox textBoxDebug;
        private System.Windows.Forms.Button buttonSendStop;
        private System.Windows.Forms.Button ListenStop;
        private System.Windows.Forms.ComboBox comboBoxServerAddress;
        private System.Windows.Forms.NumericUpDown numericUpDownServerPort;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox textBoxServerStatus;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.TextBox textBoxClientStatus;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.NumericUpDown numericUpDownClientPort;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.ComboBox comboBoxClientAddress;
        private System.Windows.Forms.Button buttonPlus;
        private System.Windows.Forms.CheckBox checkBoxServer;
        private System.Windows.Forms.CheckBox checkBoxClient;
    }
}

